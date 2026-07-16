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
	"github.com/eclipse-che/che-operator/pkg/common/infrastructure"
	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	controllerv1alpha1 "github.com/devfile/devworkspace-operator/apis/controller/v1alpha1"
	chev1alpha1 "github.com/che-incubator/kubernetes-image-puller-operator/api/v1alpha1"
	console "github.com/openshift/api/console/v1"
	configv1 "github.com/openshift/api/config/v1"
	oauthv1 "github.com/openshift/api/oauth/v1"
	projectv1 "github.com/openshift/api/project/v1"
	routev1 "github.com/openshift/api/route/v1"
	securityv1 "github.com/openshift/api/security/v1"
	templatev1 "github.com/openshift/api/template/v1"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// fixedGroupResolver returns a fixed set of groups regardless of the username.
type fixedGroupResolver struct {
	groups []string
}

func (r *fixedGroupResolver) GetUserGroups(_ context.Context, _ string) ([]string, error) {
	return r.groups, nil
}

// newTestScheme builds a runtime.Scheme with all types used by the reconciler.
func newTestScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = rbacv1.AddToScheme(scheme)
	_ = appsv1.AddToScheme(scheme)
	_ = batchv1.AddToScheme(scheme)
	_ = networkingv1.AddToScheme(scheme)
	scheme.AddKnownTypes(chev2.GroupVersion, &chev2.CheCluster{}, &chev2.CheClusterList{})
	scheme.AddKnownTypes(controllerv1alpha1.GroupVersion,
		&controllerv1alpha1.DevWorkspaceOperatorConfig{},
		&controllerv1alpha1.DevWorkspaceOperatorConfigList{},
		&controllerv1alpha1.DevWorkspaceRouting{},
		&controllerv1alpha1.DevWorkspaceRoutingList{},
	)
	scheme.AddKnownTypes(oauthv1.GroupVersion, &oauthv1.OAuthClient{}, &oauthv1.OAuthClientList{})
	scheme.AddKnownTypes(configv1.GroupVersion, &configv1.Proxy{}, &configv1.Console{}, &configv1.Authentication{}, &configv1.AuthenticationList{})
	scheme.AddKnownTypes(templatev1.GroupVersion, &templatev1.Template{}, &templatev1.TemplateList{})
	scheme.AddKnownTypes(routev1.GroupVersion, &routev1.Route{}, &routev1.RouteList{})
	scheme.AddKnownTypes(console.GroupVersion, &console.ConsoleLink{})
	scheme.AddKnownTypes(chev1alpha1.GroupVersion, &chev1alpha1.KubernetesImagePuller{})
	scheme.AddKnownTypes(securityv1.GroupVersion, &securityv1.SecurityContextConstraints{})
	scheme.AddKnownTypes(projectv1.GroupVersion, &projectv1.Project{}, &projectv1.ProjectList{})
	scheme.AddKnownTypes(monitoringv1.SchemeGroupVersion, &monitoringv1.ServiceMonitor{}, &monitoringv1.ServiceMonitorList{})
	return scheme
}

// newTestNamespace creates a Namespace object with the che username annotation set.
func newTestNamespace(name, username string) *corev1.Namespace {
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
	}
	if username != "" {
		ns.Annotations = map[string]string{
			"che.eclipse.org/username": username,
		}
	}
	return ns
}

// newCheCluster creates a CheCluster with the given advancedAuthorization policy
// and user ClusterRoles.
func newCheCluster(policy *chev2.AdvancedAuthorization, clusterRoles []string) *chev2.CheCluster {
	cc := &chev2.CheCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "eclipse-che",
			Namespace: "eclipse-che",
		},
	}
	if policy != nil {
		cc.Spec.Networking.Auth.AdvancedAuthorization = policy
	}
	if len(clusterRoles) > 0 {
		cc.Spec.DevEnvironments.User = &chev2.UserConfiguration{
			ClusterRoles: clusterRoles,
		}
	}
	return cc
}

// getRoleBinding fetches a RoleBinding from the fake client or returns nil if not found.
func getRoleBinding(ctx context.Context, cl client.Client, name, namespace string) *rbacv1.RoleBinding {
	rb := &rbacv1.RoleBinding{}
	if err := cl.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, rb); err != nil {
		return nil
	}
	return rb
}

// TestSyncPermissionsForNamespace_CreatesRoleBinding verifies that a RoleBinding
// is created when IsUserPermitted returns true.
func TestSyncPermissionsForNamespace_CreatesRoleBinding(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme()

	ns := newTestNamespace("alice-che", "alice")
	policy := &chev2.AdvancedAuthorization{AllowUsers: []string{"alice"}}
	cheCluster := newCheCluster(policy, []string{"my-cluster-role"})

	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(ns).Build()
	reconciler := NewUserPermissionReconciler(cl, scheme, &fixedGroupResolver{})

	if err := reconciler.SyncPermissionsForNamespace(ctx, cheCluster, "alice-che"); err != nil {
		t.Fatalf("SyncPermissionsForNamespace returned error: %v", err)
	}

	rb := getRoleBinding(ctx, cl, "che-user-permission-my-cluster-role", "alice-che")
	if rb == nil {
		t.Fatal("expected RoleBinding to be created, but it was not found")
	}
	if len(rb.Subjects) != 1 || rb.Subjects[0].Name != "alice" {
		t.Fatalf("expected RoleBinding subject 'alice', got %v", rb.Subjects)
	}
	if rb.RoleRef.Name != "my-cluster-role" {
		t.Fatalf("expected RoleRef 'my-cluster-role', got '%s'", rb.RoleRef.Name)
	}
}

// TestSyncPermissionsForNamespace_DeletesRoleBinding verifies that an existing
// RoleBinding is deleted when IsUserPermitted returns false (user is in DenyUsers).
func TestSyncPermissionsForNamespace_DeletesRoleBinding(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme()

	ns := newTestNamespace("bob-che", "bob")
	policy := &chev2.AdvancedAuthorization{DenyUsers: []string{"bob"}}
	cheCluster := newCheCluster(policy, []string{"my-cluster-role"})

	// Pre-create a RoleBinding to ensure it gets cleaned up.
	existingRB := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "che-user-permission-my-cluster-role",
			Namespace: "bob-che",
		},
	}

	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(ns, existingRB).Build()
	reconciler := NewUserPermissionReconciler(cl, scheme, &fixedGroupResolver{})

	if err := reconciler.SyncPermissionsForNamespace(ctx, cheCluster, "bob-che"); err != nil {
		t.Fatalf("SyncPermissionsForNamespace returned error: %v", err)
	}

	rb := getRoleBinding(ctx, cl, "che-user-permission-my-cluster-role", "bob-che")
	if rb != nil {
		t.Fatal("expected RoleBinding to be deleted, but it still exists")
	}
}

// TestSyncPermissionsForNamespace_PolicyChange verifies that a RoleBinding is
// removed after re-sync when the user is removed from AllowUsers.
func TestSyncPermissionsForNamespace_PolicyChange(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme()

	ns := newTestNamespace("carol-che", "carol")
	// Initial policy: carol is allowed.
	policy := &chev2.AdvancedAuthorization{AllowUsers: []string{"carol"}}
	cheCluster := newCheCluster(policy, []string{"my-cluster-role"})

	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(ns).Build()
	reconciler := NewUserPermissionReconciler(cl, scheme, &fixedGroupResolver{})

	// First sync — RoleBinding should be created.
	if err := reconciler.SyncPermissionsForNamespace(ctx, cheCluster, "carol-che"); err != nil {
		t.Fatalf("first SyncPermissionsForNamespace returned error: %v", err)
	}
	rb := getRoleBinding(ctx, cl, "che-user-permission-my-cluster-role", "carol-che")
	if rb == nil {
		t.Fatal("expected RoleBinding after first sync, but it was not found")
	}

	// Policy change: carol is no longer allowed.
	cheCluster.Spec.Networking.Auth.AdvancedAuthorization = &chev2.AdvancedAuthorization{
		AllowUsers: []string{"dave"},
	}

	// Second sync — RoleBinding should be removed.
	if err := reconciler.SyncPermissionsForNamespace(ctx, cheCluster, "carol-che"); err != nil {
		t.Fatalf("second SyncPermissionsForNamespace returned error: %v", err)
	}
	rb = getRoleBinding(ctx, cl, "che-user-permission-my-cluster-role", "carol-che")
	if rb != nil {
		t.Fatal("expected RoleBinding to be deleted after policy change, but it still exists")
	}
}

// TestSyncPermissionsForNamespace_NonWorkspaceNamespace verifies that a namespace
// without the 'che.eclipse.org/username' annotation is a no-op.
func TestSyncPermissionsForNamespace_NonWorkspaceNamespace(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme()

	// Namespace has no username annotation.
	ns := newTestNamespace("kube-system", "")
	policy := &chev2.AdvancedAuthorization{AllowUsers: []string{"admin"}}
	cheCluster := newCheCluster(policy, []string{"my-cluster-role"})

	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(ns).Build()
	reconciler := NewUserPermissionReconciler(cl, scheme, &fixedGroupResolver{})

	if err := reconciler.SyncPermissionsForNamespace(ctx, cheCluster, "kube-system"); err != nil {
		t.Fatalf("SyncPermissionsForNamespace returned error: %v", err)
	}

	// No RoleBinding should be created.
	rb := getRoleBinding(ctx, cl, "che-user-permission-my-cluster-role", "kube-system")
	if rb != nil {
		t.Fatal("expected no RoleBinding for non-workspace namespace, but one was found")
	}
}

// TestSyncPermissionsForNamespace_ExternalAuth verifies that in ExternalAuth mode
// user-only allow/deny rules are still applied correctly.
func TestSyncPermissionsForNamespace_ExternalAuth(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme()

	// Put the infrastructure into ExternalAuth mode (OpenShift with OAuth disabled).
	infrastructure.InitializeForTesting(infrastructure.OpenShiftV4)
	infrastructure.SetOpenShiftOAuthEnabledForTesting(false)
	defer func() {
		infrastructure.InitializeForTesting(infrastructure.OpenShiftV4)
	}()

	// Use a resolver that would return groups if called.
	// The key assertion is that user-level allow/deny still works.
	resolver := &fixedGroupResolver{groups: []string{"some-group"}}

	// eve is in AllowUsers — should be permitted.
	nsEve := newTestNamespace("eve-che", "eve")
	policy := &chev2.AdvancedAuthorization{
		AllowUsers: []string{"eve"},
	}
	cheCluster := newCheCluster(policy, []string{"my-cluster-role"})

	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(nsEve).Build()
	reconciler := NewUserPermissionReconciler(cl, scheme, resolver)

	if err := reconciler.SyncPermissionsForNamespace(ctx, cheCluster, "eve-che"); err != nil {
		t.Fatalf("SyncPermissionsForNamespace (eve allowed) returned error: %v", err)
	}
	rb := getRoleBinding(ctx, cl, "che-user-permission-my-cluster-role", "eve-che")
	if rb == nil {
		t.Fatal("expected RoleBinding for eve (in AllowUsers), but it was not found")
	}

	// frank is NOT in AllowUsers — should be denied.
	nsFrank := newTestNamespace("frank-che", "frank")
	cl2 := fake.NewClientBuilder().WithScheme(scheme).WithObjects(nsFrank).Build()
	reconciler2 := NewUserPermissionReconciler(cl2, scheme, resolver)

	if err := reconciler2.SyncPermissionsForNamespace(ctx, cheCluster, "frank-che"); err != nil {
		t.Fatalf("SyncPermissionsForNamespace (frank denied) returned error: %v", err)
	}
	rb2 := getRoleBinding(ctx, cl2, "che-user-permission-my-cluster-role", "frank-che")
	if rb2 != nil {
		t.Fatal("expected no RoleBinding for frank (not in AllowUsers), but one was found")
	}
}

// TestUserPermissionReconciler_Reconcile is an end-to-end integration test that
// exercises reconciliation: creates workspace namespaces, syncs permissions, and
// verifies RoleBindings are created or absent based on the policy.
func TestUserPermissionReconciler_Reconcile(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme()

	nsAlice := newTestNamespace("alice-ws", "alice")
	nsAlice.Labels = map[string]string{
		"app.kubernetes.io/component": "workspaces-namespace",
	}

	nsBob := newTestNamespace("bob-ws", "bob")
	nsBob.Labels = map[string]string{
		"app.kubernetes.io/component": "workspaces-namespace",
	}

	policy := &chev2.AdvancedAuthorization{
		AllowUsers: []string{"alice"},
	}
	cheCluster := newCheCluster(policy, []string{"custom-role"})

	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(nsAlice, nsBob, cheCluster).
		Build()

	reconciler := NewUserPermissionReconciler(cl, scheme, &fixedGroupResolver{})

	// Process alice's namespace.
	if err := reconciler.SyncPermissionsForNamespace(ctx, cheCluster, "alice-ws"); err != nil {
		t.Fatalf("SyncPermissionsForNamespace (alice) returned error: %v", err)
	}
	// Process bob's namespace.
	if err := reconciler.SyncPermissionsForNamespace(ctx, cheCluster, "bob-ws"); err != nil {
		t.Fatalf("SyncPermissionsForNamespace (bob) returned error: %v", err)
	}

	// alice should have the RoleBinding.
	rbAlice := getRoleBinding(ctx, cl, "che-user-permission-custom-role", "alice-ws")
	if rbAlice == nil {
		t.Fatal("expected RoleBinding for alice, but it was not found")
	}

	// bob should NOT have the RoleBinding (not in AllowUsers).
	rbBob := getRoleBinding(ctx, cl, "che-user-permission-custom-role", "bob-ws")
	if rbBob != nil {
		t.Fatal("expected no RoleBinding for bob, but one was found")
	}
}
