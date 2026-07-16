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

	"github.com/eclipse-che/che-operator/pkg/common/infrastructure"
	userv1 "github.com/openshift/api/user/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// GroupResolver resolves group memberships for a given user.
type GroupResolver interface {
	// GetUserGroups returns the names of all groups the given user belongs to.
	GetUserGroups(ctx context.Context, username string) ([]string, error)
}

// OpenShiftGroupResolver implements GroupResolver for OpenShift clusters.
// Construct it with NewOpenShiftGroupResolver(client) and pass it to IsUserPermitted
// together with the CheCluster's spec.networking.auth.advancedAuthorization policy:
//
//	resolver := NewOpenShiftGroupResolver(k8sClient)
//	permitted, err := IsUserPermitted(ctx, username, resolver, cheCluster.Spec.Networking.Auth.AdvancedAuthorization)
//	if err != nil {
//	    return err
//	}
//	// INVARIANT: if IsUserPermitted returns false, access MUST be denied.
//	if !permitted {
//	    return errors.New("user is not permitted by advanced authorization policy")
//	}
type OpenShiftGroupResolver struct {
	client client.Client
}

// NewOpenShiftGroupResolver creates a new OpenShiftGroupResolver backed by the
// given controller-runtime client. Pass the result as the GroupResolver
// argument to IsUserPermitted.
func NewOpenShiftGroupResolver(client client.Client) *OpenShiftGroupResolver {
	return &OpenShiftGroupResolver{client: client}
}

// GetUserGroups returns the groups that the given user belongs to on an
// OpenShift cluster. On Kubernetes or in ExternalAuth mode it returns nil
// (group-based rules are therefore never matched in those environments).
func (r *OpenShiftGroupResolver) GetUserGroups(ctx context.Context, username string) ([]string, error) {
	if !infrastructure.IsOpenShift() {
		return nil, nil
	}

	if infrastructure.IsOpenShiftExternalAuth() {
		// Group resolution is not supported in ExternalAuth mode.
		// Only user-based allow/deny rules apply.
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
