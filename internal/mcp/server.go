// Package mcp implements a read-only Model Context Protocol server over stdio
// (default) or Streamable HTTP (opt-in). It exposes BlakHound analysis to an
// LLM client. It never mutates AWS, never returns secrets, and never runs SQL
// or shell supplied by the client. Protocol messages go to stdout; logs to
// stderr.
package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"

	"github.com/jusso-dev/BlakHound/internal/app"
)

// protocolVersion advertised to clients.
const protocolVersion = "2024-11-05"

// Server dispatches JSON-RPC over a transport.
type Server struct {
	svc *app.Service
	log io.Writer
	mu  sync.Mutex
	out *json.Encoder
}

// NewServer builds an MCP server bound to the application service.
func NewServer(svc *app.Service, logw io.Writer) *Server {
	return &Server{svc: svc, log: logw}
}

// rpcRequest is a JSON-RPC 2.0 request/notification.
type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// ServeStdio runs the newline-delimited JSON-RPC loop over r/w.
func (s *Server) ServeStdio(ctx context.Context, r io.Reader, w io.Writer) error {
	s.out = json.NewEncoder(w)
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 1024*1024), 16*1024*1024)
	fmt.Fprintln(s.log, "blakhound mcp: stdio server ready")
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return err
		}
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var req rpcRequest
		if err := json.Unmarshal(line, &req); err != nil {
			fmt.Fprintf(s.log, "mcp: bad json: %v\n", err)
			continue
		}
		s.handle(ctx, req)
	}
	return scanner.Err()
}

func (s *Server) handle(ctx context.Context, req rpcRequest) {
	// Notifications (no id) get no response.
	isNotification := len(req.ID) == 0
	result, rerr := s.dispatch(ctx, req.Method, req.Params)
	if isNotification {
		return
	}
	resp := rpcResponse{JSONRPC: "2.0", ID: req.ID}
	if rerr != nil {
		resp.Error = rerr
	} else {
		resp.Result = result
	}
	s.write(resp)
}

func (s *Server) write(resp rpcResponse) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.out.Encode(resp); err != nil {
		fmt.Fprintf(s.log, "mcp: write error: %v\n", err)
	}
}

func (s *Server) dispatch(ctx context.Context, method string, params json.RawMessage) (any, *rpcError) {
	switch method {
	case "initialize":
		return s.onInitialize(), nil
	case "ping":
		return map[string]any{}, nil
	case "tools/list":
		return map[string]any{"tools": toolList()}, nil
	case "tools/call":
		return s.onToolCall(ctx, params)
	case "resources/list":
		return map[string]any{"resources": resourceList()}, nil
	case "resources/read":
		return s.onResourceRead(ctx, params)
	case "prompts/list":
		return map[string]any{"prompts": promptList()}, nil
	case "prompts/get":
		return s.onPromptGet(params)
	default:
		return nil, &rpcError{Code: -32601, Message: "method not found: " + method}
	}
}

// HTTPHandler returns an http.HandlerFunc implementing a minimal Streamable
// HTTP transport: each POST body is one JSON-RPC request; the response is one
// JSON-RPC message. Bound to localhost by the caller unless --allow-remote.
func (s *Server) HTTPHandler(ctx context.Context) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 16*1024*1024))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var req rpcRequest
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		result, rerr := s.dispatch(ctx, req.Method, req.Params)
		w.Header().Set("Content-Type", "application/json")
		if len(req.ID) == 0 {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		resp := rpcResponse{JSONRPC: "2.0", ID: req.ID}
		if rerr != nil {
			resp.Error = rerr
		} else {
			resp.Result = result
		}
		_ = json.NewEncoder(w).Encode(resp)
	}
}

func (s *Server) onInitialize() any {
	return map[string]any{
		"protocolVersion": protocolVersion,
		"capabilities": map[string]any{
			"tools":     map[string]any{},
			"resources": map[string]any{},
			"prompts":   map[string]any{},
		},
		"serverInfo": map[string]any{"name": "blakhound", "version": "0.1.0"},
	}
}
