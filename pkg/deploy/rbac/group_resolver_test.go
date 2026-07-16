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

	userv1 "github.com/openshift/api/user/v1"
	"github.com/eclipse-che/che-operator/pkg/common/infrastructure"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func newSchemeWithUserV1() *runtime.Scheme {
	scheme := runtime.NewScheme()
	_ = userv1.Install(scheme)
	return scheme
}

func TestGetUserGroups_NonOpenShift(t *testing.T) {
	infrastructure.InitializeForTesting(infrastructure.Kubernetes)
	defer infrastructure.InitializeForTesting(infrastructure.OpenShiftV4)

	cl := fake.NewClientBuilder().WithScheme(newSchemeWithUserV1()).Build()
	resolver := NewOpenShiftGroupResolver(cl)

	groups, err := resolver.GetUserGroups(context.Background(), "alice")
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if groups != nil {
		t.Fatalf("expected nil groups, got %v", groups)
	}
}

func TestGetUserGroups_ExternalAuth(t *testing.T) {
	infrastructure.InitializeForTesting(infrastructure.OpenShiftV4)
	infrastructure.SetOpenShiftOAuthEnabledForTesting(false)
	defer infrastructure.SetOpenShiftOAuthEnabledForTesting(true)

	cl := fake.NewClientBuilder().WithScheme(newSchemeWithUserV1()).Build()
	resolver := NewOpenShiftGroupResolver(cl)

	groups, err := resolver.GetUserGroups(context.Background(), "alice")
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if groups != nil {
		t.Fatalf("expected nil groups, got %v", groups)
	}
}

func TestGetUserGroups_NativeOAuth(t *testing.T) {
	infrastructure.InitializeForTesting(infrastructure.OpenShiftV4)

	groupAlpha := &userv1.Group{
		ObjectMeta: metav1.ObjectMeta{Name: "alpha"},
		Users:      userv1.OptionalNames{"alice", "bob"},
	}
	groupBeta := &userv1.Group{
		ObjectMeta: metav1.ObjectMeta{Name: "beta"},
		Users:      userv1.OptionalNames{"bob"},
	}

	scheme := newSchemeWithUserV1()
	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(groupAlpha, groupBeta).
		Build()

	resolver := NewOpenShiftGroupResolver(cl)

	groups, err := resolver.GetUserGroups(context.Background(), "alice")
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if len(groups) != 1 || groups[0] != "alpha" {
		t.Fatalf("expected [alpha], got %v", groups)
	}

	groups, err = resolver.GetUserGroups(context.Background(), "bob")
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if len(groups) != 2 {
		t.Fatalf("expected 2 groups for bob, got %v", groups)
	}

	groups, err = resolver.GetUserGroups(context.Background(), "carol")
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if len(groups) != 0 {
		t.Fatalf("expected empty groups for carol, got %v", groups)
	}
}
