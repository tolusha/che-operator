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

	"github.com/sirupsen/logrus"
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
// WARNING: This is a stub — implementation is deferred to T2.
// Callers will receive an empty group list; downstream authorization logic
// must not rely on this method until the full implementation is in place.
func (r *OpenShiftGroupResolver) GetUserGroups(ctx context.Context, username string) ([]string, error) {
	logrus.Warnf("GetUserGroups is not yet implemented (stub); returning empty group list for user %q", username)
	return nil, nil
}
