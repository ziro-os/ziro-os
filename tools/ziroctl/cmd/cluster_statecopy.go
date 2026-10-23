package cmd

import (
	"reflect"
	"time"
)

// The cluster state is copied for every change (a mutate works on a copy), so on every heartbeat
// of every node. That was a JSON round trip of the whole state; deepCopyInto walks it once.
//
// It follows what the round trip did: exported fields are copied deeply; unexported fields
// (lookup caches) are left out; a struct from another package that keeps its own state in
// unexported fields (time.Time, netip.Addr) is a value and copied whole.
//
// (Comparing with the last commit, hardKey, stays an encoding: a reflection walk measured no
// faster than encoding/json v2 there.)

var timeType = reflect.TypeFor[time.Time]()

// deepCopyInto copies src into dst (both settable, same type).
func deepCopyInto(dst, src reflect.Value) {
	switch src.Kind() {
	case reflect.Pointer:
		if src.IsNil() {
			return
		}
		p := reflect.New(src.Type().Elem())
		deepCopyInto(p.Elem(), src.Elem())
		dst.Set(p)
	case reflect.Slice:
		if src.IsNil() {
			return
		}
		s := reflect.MakeSlice(src.Type(), src.Len(), src.Len())
		if plainKind(src.Type().Elem()) {
			reflect.Copy(s, src)
		} else {
			for i := 0; i < src.Len(); i++ {
				deepCopyInto(s.Index(i), src.Index(i))
			}
		}
		dst.Set(s)
	case reflect.Map:
		if src.IsNil() {
			return
		}
		m := reflect.MakeMapWithSize(src.Type(), src.Len())
		it := src.MapRange()
		for it.Next() {
			if plainKind(src.Type().Elem()) {
				m.SetMapIndex(it.Key(), it.Value())
				continue
			}
			v := reflect.New(src.Type().Elem()).Elem()
			deepCopyInto(v, it.Value())
			m.SetMapIndex(it.Key(), v)
		}
		dst.Set(m)
	case reflect.Struct:
		if opaqueStruct(src.Type()) {
			dst.Set(src)
			return
		}
		t := src.Type()
		for i := 0; i < t.NumField(); i++ {
			if t.Field(i).IsExported() {
				deepCopyInto(dst.Field(i), src.Field(i))
			}
		}
	case reflect.Interface:
		if src.IsNil() {
			return
		}
		v := reflect.New(src.Elem().Type()).Elem()
		deepCopyInto(v, src.Elem())
		dst.Set(v)
	default:
		dst.Set(src)
	}
}

// plainKind: values of the type hold no references, so a plain copy is a deep copy.
func plainKind(t reflect.Type) bool {
	switch t.Kind() {
	case reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr,
		reflect.Float32, reflect.Float64, reflect.String:
		return true
	}
	return false
}

// opaqueStruct: a struct of another package with unexported fields is an opaque value (time.Time,
// netip.Addr, ...): copied and compared as a whole, as its own JSON encoding treats it.
func opaqueStruct(t reflect.Type) bool {
	if t == timeType {
		return true
	}
	if t.PkgPath() == reflect.TypeFor[ClusterState]().PkgPath() {
		return false
	}
	for i := 0; i < t.NumField(); i++ {
		if !t.Field(i).IsExported() {
			return true
		}
	}
	return false
}
