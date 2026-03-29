// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// log-collector receives webhook events from pipelock's emit pipeline and
// stores them for querying. This proves pipelock not only blocked but LOGGED
// every detection — critical for SecureIQLab scoring.
//
// Endpoints:
//
//	POST /events          - receive webhook events (pipelock emit target)
//	GET  /events          - list all stored events (JSONL)
//	GET  /events?type=X   - filter events by event_type
//	GET  /events/count    - total event count
//	GET  /events/summary  - count by event_type
//	GET  /health          - health check
//	DELETE /events        - clear all events (for test reset)
//
// Environment variables:
//
//	LOG_COLLECTOR_LISTEN  - listen address (default ":9090")
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
)

type event struct {
	ReceivedAt time.Time      `json:"received_at"`
	Payload    map[string]any `json:"payload"`
}

type store struct {
	mu     sync.RWMutex
	events []event
}

func (s *store) add(payload map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, event{
		ReceivedAt: time.Now().UTC(),
		Payload:    payload,
	})
}

func (s *store) list(eventType string) []event {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if eventType == "" {
		result := make([]event, len(s.events))
		copy(result, s.events)
		return result
	}

	var filtered []event
	for _, e := range s.events {
		if et, ok := e.Payload["event_type"].(string); ok && et == eventType {
			filtered = append(filtered, e)
		}
	}
	return filtered
}

func (s *store) count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.events)
}

func (s *store) summary() map[string]int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	counts := make(map[string]int)
	for _, e := range s.events {
		et, _ := e.Payload["event_type"].(string)
		if et == "" {
			et = "unknown"
		}
		counts[et]++
	}
	return counts
}

func (s *store) clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = nil
}

func main() {
	listen := os.Getenv("LOG_COLLECTOR_LISTEN")
	if listen == "" {
		listen = ":9090"
	}

	s := &store{}
	mux := http.NewServeMux()

	// Receive webhook events from pipelock.
	mux.HandleFunc("POST /events", func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
			return
		}
		s.add(payload)
		log.Printf("event received: type=%v severity=%v",
			payload["event_type"], payload["severity"])
		w.WriteHeader(http.StatusAccepted)
		_, _ = fmt.Fprint(w, `{"status":"accepted"}`)
	})

	// List events, with optional type filter.
	mux.HandleFunc("GET /events", func(w http.ResponseWriter, r *http.Request) {
		eventType := r.URL.Query().Get("type")
		events := s.list(eventType)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"count":  len(events),
			"events": events,
		})
	})

	// Event count.
	mux.HandleFunc("GET /events/count", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"count":%d}`, s.count())
	})

	// Summary: count by event type.
	mux.HandleFunc("GET /events/summary", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(s.summary())
	})

	// Clear events (for test reset).
	mux.HandleFunc("DELETE /events", func(w http.ResponseWriter, _ *http.Request) {
		s.clear()
		_, _ = fmt.Fprint(w, `{"status":"cleared"}`)
	})

	// Health check.
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"status":"ok","events":%d}`, s.count())
	})

	log.Printf("log-collector starting on %s", listen)
	srv := &http.Server{
		Addr:              listen,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
