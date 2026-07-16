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

	userv1 "github.com/openshift/api/user/v1"
	"github.com/eclipse-che/che-operator/pkg/common/infrastructure"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// GroupResolver resolves group memberships for a given user.
type GroupResolver interface {
	GetUserGroups(ctx context.Context, username string) ([]string, error)
}

// OpenShiftGroupResolver implements GroupResolver for OpenShift clusters.
type OpenShiftGroupResolver struct {
	client client.Client
}

// NewOpenShiftGroupResolver creates a new OpenShiftGroupResolver.
func NewOpenShiftGroupResolver(client client.Client) *OpenShiftGroupResolver {
	return &OpenShiftGroupResolver{client: client}
}

// GetUserGroups returns the groups that the given user belongs to.
func (r *OpenShiftGroupResolver) GetUserGroups(ctx context.Context, username string) ([]string, error) {
	if !infrastructure.IsOpenShift() {
		return nil, nil
	}

	if infrastructure.IsOpenShiftExternalAuth() {
		// Group resolution is not supported in ExternalAuth mode. Only user-based allow/deny rules apply.
		// Contact your OIDC provider to use groups-based access control.
		return nil, nil
	}

	groupList := &userv1.GroupList{}
	if err := r.client.List(ctx, groupList); err != nil {
		return nil, err
	}

	var groups []string
	for _, group := range groupList.Items {
		for _, user := range group.Users {
			if user == username {
				groups = append(groups, group.Name)
				break
			}
		}
	}

	return groups, nil
}
