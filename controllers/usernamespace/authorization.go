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

	v2 "github.com/eclipse-che/che-operator/api/v2"
	"github.com/eclipse-che/che-operator/pkg/common/infrastructure"
	userv1 "github.com/openshift/api/user/v1"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// isUserAuthorized checks whether the given username is authorized according to the AdvancedAuthorization rules.
// If advAuth is nil, all users are authorized. If AllowUsers and AllowGroups are both empty, all users are allowed
// by default; otherwise the user must be in AllowUsers OR a member of any group in AllowGroups. The user is then
// denied if in DenyUsers OR a member of any group in DenyGroups.
// On Kubernetes (non-OpenShift OAuth), group checks are skipped.
func isUserAuthorized(ctx context.Context, cl client.Client, advAuth *v2.AdvancedAuthorization, username string) (bool, error) {
	if advAuth == nil {
		return true, nil
	}

	// Determine if we should check allow rules.
	// If both AllowUsers and AllowGroups are empty, all users are allowed by default.
	hasAllowRules := len(advAuth.AllowUsers) > 0 || len(advAuth.AllowGroups) > 0

	allowed := !hasAllowRules

	if !allowed {
		// Check AllowUsers
		for _, u := range advAuth.AllowUsers {
			if u == username {
				allowed = true
				break
			}
		}
	}

	// Check AllowGroups (OpenShift only)
	if !allowed && infrastructure.IsOpenShiftOAuthEnabled() && len(advAuth.AllowGroups) > 0 {
		for _, groupName := range advAuth.AllowGroups {
			member, err := isUserInGroup(ctx, cl, username, groupName)
			if err != nil {
				// Group lookup unavailable — skip this group (fail-open)
				logrus.Warnf("Group lookup unavailable, skipping group-based authorization for group %s", groupName)
				continue
			}
			if member {
				allowed = true
				break
			}
		}
	}

	if !allowed {
		return false, nil
	}

	// Check DenyUsers
	for _, u := range advAuth.DenyUsers {
		if u == username {
			return false, nil
		}
	}

	// Check DenyGroups (OpenShift only)
	if infrastructure.IsOpenShiftOAuthEnabled() && len(advAuth.DenyGroups) > 0 {
		for _, groupName := range advAuth.DenyGroups {
			member, err := isUserInGroup(ctx, cl, username, groupName)
			if err != nil {
				// Group lookup unavailable — skip this group (fail-open)
				logrus.Warnf("Group lookup unavailable, skipping group-based authorization for group %s", groupName)
				continue
			}
			if member {
				return false, nil
			}
		}
	}

	return true, nil
}

// isUserInGroup checks whether the given username is a member of the OpenShift group with the given name.
// Returns an error if the group cannot be looked up (other than NotFound).
func isUserInGroup(ctx context.Context, cl client.Client, username string, groupName string) (bool, error) {
	group := &userv1.Group{}
	if err := cl.Get(ctx, types.NamespacedName{Name: groupName}, group); err != nil {
		if errors.IsNotFound(err) {
			return false, nil
		}
		return false, err
	}
	for _, u := range group.Users {
		if u == username {
			return true, nil
		}
	}
	return false, nil
}
