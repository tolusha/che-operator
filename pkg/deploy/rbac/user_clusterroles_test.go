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
	"fmt"
	"testing"

	"github.com/eclipse-che/che-operator/pkg/common/constants"
	"github.com/eclipse-che/che-operator/pkg/common/infrastructure"
	"github.com/eclipse-che/che-operator/pkg/common/test"
	"github.com/eclipse-che/che-operator/pkg/common/utils"
	"github.com/stretchr/testify/assert"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/types"
)

func TestUserClusterRolesReconciler_ReconcileCreatesBothClusterRoles(t *testing.T) {
	infrastructure.InitializeForTesting(infrastructure.Kubernetes)

	ctx := test.NewCtxBuilder().Build()
	reconciler := NewUserClusterRolesReconciler()

	test.EnsureReconcile(t, ctx, reconciler.Reconcile)

	namespace := ctx.CheCluster.Namespace
	commonName := fmt.Sprintf(constants.UserCommonPermissionsTemplateName, namespace)
	devworkspaceName := fmt.Sprintf(constants.UserDevWorkspacePermissionsTemplateName, namespace)

	// Both ClusterRoles should exist
	assert.True(t, test.IsObjectExists(ctx.ClusterAPI.Client, types.NamespacedName{Name: commonName}, &rbacv1.ClusterRole{}))
	assert.True(t, test.IsObjectExists(ctx.ClusterAPI.Client, types.NamespacedName{Name: devworkspaceName}, &rbacv1.ClusterRole{}))

	// Verify common ClusterRole has expected k8s policy rules
	commonRole := &rbacv1.ClusterRole{}
	err := ctx.ClusterAPI.Client.Get(context.TODO(), types.NamespacedName{Name: commonName}, commonRole)
	assert.NoError(t, err)
	assert.NotEmpty(t, commonRole.Rules)

	// Verify at least one expected k8s rule is present (pods/exec)
	foundPodsExec := false
	for _, rule := range commonRole.Rules {
		for _, res := range rule.Resources {
			if res == "pods/exec" {
				foundPodsExec = true
			}
		}
	}
	assert.True(t, foundPodsExec, "expected pods/exec rule in common ClusterRole")

	// Verify devworkspace ClusterRole has devworkspace policy rules
	devworkspaceRole := &rbacv1.ClusterRole{}
	err = ctx.ClusterAPI.Client.Get(context.TODO(), types.NamespacedName{Name: devworkspaceName}, devworkspaceRole)
	assert.NoError(t, err)
	assert.NotEmpty(t, devworkspaceRole.Rules)

	foundDevWorkspaces := false
	for _, rule := range devworkspaceRole.Rules {
		for _, res := range rule.Resources {
			if res == "devworkspaces" {
				foundDevWorkspaces = true
			}
		}
	}
	assert.True(t, foundDevWorkspaces, "expected devworkspaces rule in devworkspace ClusterRole")

	// Verify finalizers were added
	assert.True(t, utils.Contains(ctx.CheCluster.Finalizers, UserCommonClusterRoleFinalizerName))
	assert.True(t, utils.Contains(ctx.CheCluster.Finalizers, UserDevWorkspaceClusterRoleFinalizerName))
}

func TestUserClusterRolesReconciler_OpenShiftConditionalRulesAdded(t *testing.T) {
	infrastructure.InitializeForTesting(infrastructure.OpenShiftV4)
	defer infrastructure.InitializeForTesting(infrastructure.OpenShiftV4)

	ctx := test.NewCtxBuilder().Build()
	reconciler := NewUserClusterRolesReconciler()

	test.EnsureReconcile(t, ctx, reconciler.Reconcile)

	namespace := ctx.CheCluster.Namespace
	commonName := fmt.Sprintf(constants.UserCommonPermissionsTemplateName, namespace)

	commonRole := &rbacv1.ClusterRole{}
	err := ctx.ClusterAPI.Client.Get(context.TODO(), types.NamespacedName{Name: commonName}, commonRole)
	assert.NoError(t, err)

	// On OpenShift, route.openshift.io/routes and project.openshift.io/projects rules should be present
	foundRoutes := false
	foundProjects := false
	for _, rule := range commonRole.Rules {
		for _, res := range rule.Resources {
			if res == "routes" {
				foundRoutes = true
			}
			if res == "projects" {
				foundProjects = true
			}
		}
	}
	assert.True(t, foundRoutes, "expected routes rule in common ClusterRole on OpenShift")
	assert.True(t, foundProjects, "expected projects rule in common ClusterRole on OpenShift")
}

func TestUserClusterRolesReconciler_KubernetesNoOpenShiftRules(t *testing.T) {
	infrastructure.InitializeForTesting(infrastructure.Kubernetes)

	ctx := test.NewCtxBuilder().Build()
	reconciler := NewUserClusterRolesReconciler()

	test.EnsureReconcile(t, ctx, reconciler.Reconcile)

	namespace := ctx.CheCluster.Namespace
	commonName := fmt.Sprintf(constants.UserCommonPermissionsTemplateName, namespace)

	commonRole := &rbacv1.ClusterRole{}
	err := ctx.ClusterAPI.Client.Get(context.TODO(), types.NamespacedName{Name: commonName}, commonRole)
	assert.NoError(t, err)

	// On Kubernetes, OpenShift-specific rules should NOT be present
	foundRoutes := false
	foundProjects := false
	for _, rule := range commonRole.Rules {
		for _, res := range rule.Resources {
			if res == "routes" {
				foundRoutes = true
			}
			if res == "projects" {
				foundProjects = true
			}
		}
	}
	assert.False(t, foundRoutes, "routes rule should not be present on Kubernetes")
	assert.False(t, foundProjects, "projects rule should not be present on Kubernetes")
}

func TestUserClusterRolesReconciler_FinalizeDeletesBothClusterRolesAndFinalizers(t *testing.T) {
	infrastructure.InitializeForTesting(infrastructure.Kubernetes)

	ctx := test.NewCtxBuilder().Build()
	reconciler := NewUserClusterRolesReconciler()

	// First reconcile to create the resources
	test.EnsureReconcile(t, ctx, reconciler.Reconcile)

	namespace := ctx.CheCluster.Namespace
	commonName := fmt.Sprintf(constants.UserCommonPermissionsTemplateName, namespace)
	devworkspaceName := fmt.Sprintf(constants.UserDevWorkspacePermissionsTemplateName, namespace)

	// Confirm they exist before finalize
	assert.True(t, test.IsObjectExists(ctx.ClusterAPI.Client, types.NamespacedName{Name: commonName}, &rbacv1.ClusterRole{}))
	assert.True(t, test.IsObjectExists(ctx.ClusterAPI.Client, types.NamespacedName{Name: devworkspaceName}, &rbacv1.ClusterRole{}))
	assert.True(t, utils.Contains(ctx.CheCluster.Finalizers, UserCommonClusterRoleFinalizerName))
	assert.True(t, utils.Contains(ctx.CheCluster.Finalizers, UserDevWorkspaceClusterRoleFinalizerName))

	// Finalize
	done := reconciler.Finalize(ctx)
	assert.True(t, done)

	// Both ClusterRoles should be gone
	assert.False(t, test.IsObjectExists(ctx.ClusterAPI.Client, types.NamespacedName{Name: commonName}, &rbacv1.ClusterRole{}))
	assert.False(t, test.IsObjectExists(ctx.ClusterAPI.Client, types.NamespacedName{Name: devworkspaceName}, &rbacv1.ClusterRole{}))

	// Finalizers should be removed
	assert.False(t, utils.Contains(ctx.CheCluster.Finalizers, UserCommonClusterRoleFinalizerName))
	assert.False(t, utils.Contains(ctx.CheCluster.Finalizers, UserDevWorkspaceClusterRoleFinalizerName))
}

func TestUserClusterRolesReconciler_ReconcileIsIdempotent(t *testing.T) {
	infrastructure.InitializeForTesting(infrastructure.Kubernetes)

	ctx := test.NewCtxBuilder().Build()
	reconciler := NewUserClusterRolesReconciler()

	// First reconcile
	test.EnsureReconcile(t, ctx, reconciler.Reconcile)

	namespace := ctx.CheCluster.Namespace
	commonName := fmt.Sprintf(constants.UserCommonPermissionsTemplateName, namespace)
	devworkspaceName := fmt.Sprintf(constants.UserDevWorkspacePermissionsTemplateName, namespace)

	// Second reconcile - should not error and resources should still be present
	_, done, err := reconciler.Reconcile(ctx)
	assert.NoError(t, err)
	assert.True(t, done)

	// Resources should still exist
	assert.True(t, test.IsObjectExists(ctx.ClusterAPI.Client, types.NamespacedName{Name: commonName}, &rbacv1.ClusterRole{}))
	assert.True(t, test.IsObjectExists(ctx.ClusterAPI.Client, types.NamespacedName{Name: devworkspaceName}, &rbacv1.ClusterRole{}))

	// Finalizers should still be set
	assert.True(t, utils.Contains(ctx.CheCluster.Finalizers, UserCommonClusterRoleFinalizerName))
	assert.True(t, utils.Contains(ctx.CheCluster.Finalizers, UserDevWorkspaceClusterRoleFinalizerName))
}
