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

package usernamespace

import (
	"context"
	"testing"

	v2 "github.com/eclipse-che/che-operator/api/v2"
	"github.com/eclipse-che/che-operator/pkg/common/infrastructure"
	userv1 "github.com/openshift/api/user/v1"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// newFakeClientWithGroups builds a fake client using the custom scheme from
// newSchemeWithUserv1() (defined in init_test.go) so that userv1.Group objects
// can be seeded and retrieved without panic. The shared test client
// (pkg/common/test/test-client) does NOT register userv1.Group, so we must
// use this isolated client for authorization tests.
func newFakeClientWithGroups(groups ...*userv1.Group) *fake.ClientBuilder {
	scheme := newSchemeWithUserv1()
	builder := fake.NewClientBuilder().WithScheme(scheme)
	for _, g := range groups {
		builder = builder.WithObjects(g)
	}
	return builder
}

func TestIsUserAuthorized(t *testing.T) {
	ctx := context.TODO()

	tests := []struct {
		name        string
		advAuth     *v2.AdvancedAuthorization
		username    string
		infraType   infrastructure.Type
		seedGroups  []*userv1.Group
		wantAllowed bool
		wantErr     bool
	}{
		{
			name:        "nil AdvancedAuthorization allows all users",
			advAuth:     nil,
			username:    "alice",
			infraType:   infrastructure.OpenShiftV4,
			wantAllowed: true,
		},
		{
			name: "empty allow lists allow all users",
			advAuth: &v2.AdvancedAuthorization{
				AllowUsers:  []string{},
				AllowGroups: []string{},
				DenyUsers:   []string{},
				DenyGroups:  []string{},
			},
			username:    "alice",
			infraType:   infrastructure.OpenShiftV4,
			wantAllowed: true,
		},
		{
			name: "user in AllowUsers is allowed",
			advAuth: &v2.AdvancedAuthorization{
				AllowUsers: []string{"alice", "bob"},
			},
			username:    "alice",
			infraType:   infrastructure.OpenShiftV4,
			wantAllowed: true,
		},
		{
			name: "user NOT in AllowUsers (non-empty list) is denied",
			advAuth: &v2.AdvancedAuthorization{
				AllowUsers: []string{"alice", "bob"},
			},
			username:    "charlie",
			infraType:   infrastructure.OpenShiftV4,
			wantAllowed: false,
		},
		{
			name: "user in DenyUsers is denied even if also in AllowUsers",
			advAuth: &v2.AdvancedAuthorization{
				AllowUsers: []string{"alice"},
				DenyUsers:  []string{"alice"},
			},
			username:    "alice",
			infraType:   infrastructure.OpenShiftV4,
			wantAllowed: false,
		},
		{
			name: "on OpenShift user in AllowGroups group is allowed",
			advAuth: &v2.AdvancedAuthorization{
				AllowGroups: []string{"devs"},
			},
			username:  "alice",
			infraType: infrastructure.OpenShiftV4,
			seedGroups: []*userv1.Group{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "devs"},
					Users:      userv1.OptionalNames{"alice", "bob"},
				},
			},
			wantAllowed: true,
		},
		{
			name: "on OpenShift user in DenyGroups group is denied",
			advAuth: &v2.AdvancedAuthorization{
				AllowUsers: []string{"alice"},
				DenyGroups: []string{"banned"},
			},
			username:  "alice",
			infraType: infrastructure.OpenShiftV4,
			seedGroups: []*userv1.Group{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "banned"},
					Users:      userv1.OptionalNames{"alice"},
				},
			},
			wantAllowed: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			infrastructure.InitializeForTesting(tt.infraType)

			cl := newFakeClientWithGroups(tt.seedGroups...).Build()

			got, err := isUserAuthorized(ctx, cl, tt.advAuth, tt.username)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantAllowed, got)
			}
		})
	}
}
