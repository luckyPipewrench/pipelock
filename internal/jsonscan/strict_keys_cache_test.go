// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package jsonscan

import (
	"reflect"
	"sync"
	"testing"
)

type cacheBenchLeaf struct {
	Name   string            `json:"name"`
	Labels map[string]string `json:"labels"`
}

type cacheBenchNested struct {
	ID     string           `json:"id"`
	Leaf   cacheBenchLeaf   `json:"leaf"`
	Leaves []cacheBenchLeaf `json:"leaves"`
}

type cacheBenchDocument struct {
	cacheBenchNested `json:"nested"`
	Items            []cacheBenchNested        `json:"items"`
	Index            map[string]cacheBenchLeaf `json:"index"`
	Token            string                    `json:"token"`
}

type (
	cacheAmbiguousFirst    struct{ Key string }
	cacheAmbiguousSecond   struct{ Key string }
	cacheAmbiguousDocument struct {
		cacheAmbiguousFirst
		cacheAmbiguousSecond
	}
)

type cacheConcurrentDocument struct {
	*cacheConcurrentDocument
	Value string `json:"value"`
}

var cacheBenchType = reflect.TypeFor[cacheBenchDocument]()

func BenchmarkStructFieldsUncached(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		_ = structFields(cacheBenchType, make(map[reflect.Type]bool))
	}
}

func BenchmarkStructFieldsCached(b *testing.B) {
	_ = cachedStructFields(cacheBenchType)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = cachedStructFields(cacheBenchType)
	}
}

func TestCachedStructFieldsMatchUncached(t *testing.T) {
	for _, typ := range []reflect.Type{
		reflect.TypeFor[aliasLeaf](),
		reflect.TypeFor[aliasEmbedded](),
		reflect.TypeFor[aliasRecursive](),
		reflect.TypeFor[cacheAmbiguousDocument](),
		cacheBenchType,
	} {
		t.Run(typ.String(), func(t *testing.T) {
			want := structFields(typ, make(map[reflect.Type]bool))
			got := cachedStructFields(typ)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("cached schema differs from uncached schema:\n got: %#v\nwant: %#v", got, want)
			}
		})
	}
}

func TestStructFieldsCacheConcurrentCold(t *testing.T) {
	const workers = 32
	typ := reflect.TypeFor[cacheConcurrentDocument]()
	recursive := reflect.TypeOf(cacheConcurrentDocument{}.cacheConcurrentDocument)
	if field := typ.Field(0); !field.Anonymous || field.Type != recursive || recursive != reflect.PointerTo(typ) {
		t.Fatal("concurrent cache fixture must embed a pointer to itself")
	}
	want := structFields(typ, make(map[reflect.Type]bool))
	structFieldCache.Delete(typ)
	start := make(chan struct{})
	results := make(chan map[string]schemaField, workers)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			results <- cachedStructFields(typ)
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	for got := range results {
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("concurrent cached schema differs from uncached schema:\n got: %#v\nwant: %#v", got, want)
		}
	}
}
