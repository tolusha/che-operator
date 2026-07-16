//
// Copyright (c) 2019-2026 Red Hat, Inc.
// This program and the accompanying materials are made
// available under the terms of the Eclipse Public License 2.0
// which is available at https://www.eclipse.org/legal/epl-2.0/
//
// SPDX-License-Identifier: EPL-2.0
//
// Contributors:
//   Red Hat, Inc. - initial API and implementation
//

package rbac

import (
	"context"
	"testing"

	chev2 "github.com/eclipse-che/che-operator/api/v2"
)

// mockGroupResolver is a simple GroupResolver that returns a fixed group list.
type mockGroupResolver struct {
	groups []string
}

func (m *mockGroupResolver) GetUserGroups(_ context.Context, _ string) ([]string, error) {
	return m.groups, nil
}

func TestIsUserPermitted_EmptyPolicy(t *testing.T) {
	resolver := &mockGroupResolver{}
	policy := chev2.AdvancedAuthorization{}

	permitted, err := IsUserPermitted(context.Background(), "alice", resolver, policy)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !permitted {
		t.Fatal("expected empty policy to permit all users")
	}
}

func TestIsUserPermitted_DenyUsers(t *testing.T) {
	resolver := &mockGroupResolver{}
	policy := chev2.AdvancedAuthorization{
		DenyUsers: []string{"alice"},
	}

	permitted, err := IsUserPermitted(context.Background(), "alice", resolver, policy)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if permitted {
		t.Fatal("expected alice to be denied")
	}

	// bob is not in deny list — should be permitted.
	permitted, err = IsUserPermitted(context.Background(), "bob", resolver, policy)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !permitted {
		t.Fatal("expected bob to be permitted")
	}
}

func TestIsUserPermitted_DenyGroups(t *testing.T) {
	// alice belongs to "banned-group".
	resolver := &mockGroupResolver{groups: []string{"banned-group"}}
	policy := chev2.AdvancedAuthorization{
		DenyGroups: []string{"banned-group"},
	}

	permitted, err := IsUserPermitted(context.Background(), "alice", resolver, policy)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if permitted {
		t.Fatal("expected alice (in banned-group) to be denied")
	}
}

func TestIsUserPermitted_AllowUsers_Matched(t *testing.T) {
	resolver := &mockGroupResolver{}
	policy := chev2.AdvancedAuthorization{
		AllowUsers: []string{"alice"},
	}

	permitted, err := IsUserPermitted(context.Background(), "alice", resolver, policy)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !permitted {
		t.Fatal("expected alice to be permitted by AllowUsers")
	}
}

func TestIsUserPermitted_AllowUsers_Unmatched(t *testing.T) {
	resolver := &mockGroupResolver{}
	policy := chev2.AdvancedAuthorization{
		AllowUsers: []string{"alice"},
	}

	permitted, err := IsUserPermitted(context.Background(), "bob", resolver, policy)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if permitted {
		t.Fatal("expected bob to be blocked when not in AllowUsers")
	}
}

func TestIsUserPermitted_DenyWinsOverAllow(t *testing.T) {
	resolver := &mockGroupResolver{}
	policy := chev2.AdvancedAuthorization{
		AllowUsers: []string{"alice"},
		DenyUsers:  []string{"alice"},
	}

	permitted, err := IsUserPermitted(context.Background(), "alice", resolver, policy)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if permitted {
		t.Fatal("expected deny to win over allow for alice")
	}
}
