package schema

import "testing"

func TestPostgresConfigKindAndParse(t *testing.T) {
	y := []byte("postgres:\n  version: 1\n  name: shop\n  replicas: 3\n  paused: false\n")
	if k, err := Kind(y); err != nil || k != "postgres" {
		t.Fatalf("kind %q %v", k, err)
	}
	c, err := ParsePostgresConfig(y)
	if err != nil {
		t.Fatal(err)
	}
	if c.Postgres.Name != "shop" || c.Postgres.Replicas == nil || *c.Postgres.Replicas != 3 || c.Postgres.Paused == nil || *c.Postgres.Paused {
		t.Fatalf("%+v", c.Postgres)
	}
	// Left out stays nil: the cluster keeps its value.
	c, _ = ParsePostgresConfig([]byte(`{"postgres": {"version": 1, "name": "shop"}}`))
	if c.Postgres.Replicas != nil || c.Postgres.Paused != nil || c.Postgres.Backup != nil || c.Postgres.Params != nil {
		t.Fatalf("defaults filled in: %+v", c.Postgres)
	}
	if _, err := ParsePostgresConfig([]byte("postgres: {version: 1, name: shop}\nhost: {}\n")); err == nil {
		t.Fatal("an unknown top-level field is refused")
	}
}
