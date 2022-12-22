//go:build !ignore_autogenerated
// +build !ignore_autogenerated

//
// Copyright (c) 2019-2022 Red Hat, Inc.
// This program and the accompanying materials are made
// available under the terms of the Eclipse Public License 2.0
// which is available at https://www.eclipse.org/legal/epl-2.0/
//
// SPDX-License-Identifier: EPL-2.0
//
// Contributors:
//   Red Hat, Inc. - initial API and implementation
//

// Code generated by controller-gen. DO NOT EDIT.

package v1

import (
	"github.com/devfile/api/v2/pkg/apis/workspaces/v1alpha2"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *BitBucketService) DeepCopyInto(out *BitBucketService) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new BitBucketService.
func (in *BitBucketService) DeepCopy() *BitBucketService {
	if in == nil {
		return nil
	}
	out := new(BitBucketService)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CheCluster) DeepCopyInto(out *CheCluster) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	out.Status = in.Status
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CheCluster.
func (in *CheCluster) DeepCopy() *CheCluster {
	if in == nil {
		return nil
	}
	out := new(CheCluster)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *CheCluster) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CheClusterGitServices) DeepCopyInto(out *CheClusterGitServices) {
	*out = *in
	if in.GitHub != nil {
		in, out := &in.GitHub, &out.GitHub
		*out = make([]GitHubService, len(*in))
		copy(*out, *in)
	}
	if in.GitLab != nil {
		in, out := &in.GitLab, &out.GitLab
		*out = make([]GitLabService, len(*in))
		copy(*out, *in)
	}
	if in.BitBucket != nil {
		in, out := &in.BitBucket, &out.BitBucket
		*out = make([]BitBucketService, len(*in))
		copy(*out, *in)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CheClusterGitServices.
func (in *CheClusterGitServices) DeepCopy() *CheClusterGitServices {
	if in == nil {
		return nil
	}
	out := new(CheClusterGitServices)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CheClusterList) DeepCopyInto(out *CheClusterList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]CheCluster, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CheClusterList.
func (in *CheClusterList) DeepCopy() *CheClusterList {
	if in == nil {
		return nil
	}
	out := new(CheClusterList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *CheClusterList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CheClusterSpec) DeepCopyInto(out *CheClusterSpec) {
	*out = *in
	in.Server.DeepCopyInto(&out.Server)
	in.Database.DeepCopyInto(&out.Database)
	in.Auth.DeepCopyInto(&out.Auth)
	out.Storage = in.Storage
	out.Dashboard = in.Dashboard
	out.Metrics = in.Metrics
	out.K8s = in.K8s
	out.ImagePuller = in.ImagePuller
	in.DevWorkspace.DeepCopyInto(&out.DevWorkspace)
	in.GitServices.DeepCopyInto(&out.GitServices)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CheClusterSpec.
func (in *CheClusterSpec) DeepCopy() *CheClusterSpec {
	if in == nil {
		return nil
	}
	out := new(CheClusterSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CheClusterSpecAuth) DeepCopyInto(out *CheClusterSpecAuth) {
	*out = *in
	if in.InitialOpenShiftOAuthUser != nil {
		in, out := &in.InitialOpenShiftOAuthUser, &out.InitialOpenShiftOAuthUser
		*out = new(bool)
		**out = **in
	}
	if in.OpenShiftoAuth != nil {
		in, out := &in.OpenShiftoAuth, &out.OpenShiftoAuth
		*out = new(bool)
		**out = **in
	}
	in.IdentityProviderIngress.DeepCopyInto(&out.IdentityProviderIngress)
	in.IdentityProviderRoute.DeepCopyInto(&out.IdentityProviderRoute)
	out.IdentityProviderContainerResources = in.IdentityProviderContainerResources
	if in.NativeUserMode != nil {
		in, out := &in.NativeUserMode, &out.NativeUserMode
		*out = new(bool)
		**out = **in
	}
	if in.GatewayEnv != nil {
		in, out := &in.GatewayEnv, &out.GatewayEnv
		*out = make([]corev1.EnvVar, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.GatewayConfigBumpEnv != nil {
		in, out := &in.GatewayConfigBumpEnv, &out.GatewayConfigBumpEnv
		*out = make([]corev1.EnvVar, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.GatewayOAuthProxyEnv != nil {
		in, out := &in.GatewayOAuthProxyEnv, &out.GatewayOAuthProxyEnv
		*out = make([]corev1.EnvVar, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.GatewayKubeRbacProxyEnv != nil {
		in, out := &in.GatewayKubeRbacProxyEnv, &out.GatewayKubeRbacProxyEnv
		*out = make([]corev1.EnvVar, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CheClusterSpecAuth.
func (in *CheClusterSpecAuth) DeepCopy() *CheClusterSpecAuth {
	if in == nil {
		return nil
	}
	out := new(CheClusterSpecAuth)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CheClusterSpecDB) DeepCopyInto(out *CheClusterSpecDB) {
	*out = *in
	out.ChePostgresContainerResources = in.ChePostgresContainerResources
	if in.PostgresEnv != nil {
		in, out := &in.PostgresEnv, &out.PostgresEnv
		*out = make([]corev1.EnvVar, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CheClusterSpecDB.
func (in *CheClusterSpecDB) DeepCopy() *CheClusterSpecDB {
	if in == nil {
		return nil
	}
	out := new(CheClusterSpecDB)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CheClusterSpecDashboard) DeepCopyInto(out *CheClusterSpecDashboard) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CheClusterSpecDashboard.
func (in *CheClusterSpecDashboard) DeepCopy() *CheClusterSpecDashboard {
	if in == nil {
		return nil
	}
	out := new(CheClusterSpecDashboard)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CheClusterSpecDevWorkspace) DeepCopyInto(out *CheClusterSpecDevWorkspace) {
	*out = *in
	if in.SecondsOfInactivityBeforeIdling != nil {
		in, out := &in.SecondsOfInactivityBeforeIdling, &out.SecondsOfInactivityBeforeIdling
		*out = new(int32)
		**out = **in
	}
	if in.SecondsOfRunBeforeIdling != nil {
		in, out := &in.SecondsOfRunBeforeIdling, &out.SecondsOfRunBeforeIdling
		*out = new(int32)
		**out = **in
	}
	if in.Env != nil {
		in, out := &in.Env, &out.Env
		*out = make([]corev1.EnvVar, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CheClusterSpecDevWorkspace.
func (in *CheClusterSpecDevWorkspace) DeepCopy() *CheClusterSpecDevWorkspace {
	if in == nil {
		return nil
	}
	out := new(CheClusterSpecDevWorkspace)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CheClusterSpecImagePuller) DeepCopyInto(out *CheClusterSpecImagePuller) {
	*out = *in
	out.Spec = in.Spec
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CheClusterSpecImagePuller.
func (in *CheClusterSpecImagePuller) DeepCopy() *CheClusterSpecImagePuller {
	if in == nil {
		return nil
	}
	out := new(CheClusterSpecImagePuller)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CheClusterSpecK8SOnly) DeepCopyInto(out *CheClusterSpecK8SOnly) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CheClusterSpecK8SOnly.
func (in *CheClusterSpecK8SOnly) DeepCopy() *CheClusterSpecK8SOnly {
	if in == nil {
		return nil
	}
	out := new(CheClusterSpecK8SOnly)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CheClusterSpecMetrics) DeepCopyInto(out *CheClusterSpecMetrics) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CheClusterSpecMetrics.
func (in *CheClusterSpecMetrics) DeepCopy() *CheClusterSpecMetrics {
	if in == nil {
		return nil
	}
	out := new(CheClusterSpecMetrics)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CheClusterSpecServer) DeepCopyInto(out *CheClusterSpecServer) {
	*out = *in
	if in.AllowAutoProvisionUserNamespace != nil {
		in, out := &in.AllowAutoProvisionUserNamespace, &out.AllowAutoProvisionUserNamespace
		*out = new(bool)
		**out = **in
	}
	if in.DisableInternalClusterSVCNames != nil {
		in, out := &in.DisableInternalClusterSVCNames, &out.DisableInternalClusterSVCNames
		*out = new(bool)
		**out = **in
	}
	in.DashboardIngress.DeepCopyInto(&out.DashboardIngress)
	in.DashboardRoute.DeepCopyInto(&out.DashboardRoute)
	in.DevfileRegistryIngress.DeepCopyInto(&out.DevfileRegistryIngress)
	in.DevfileRegistryRoute.DeepCopyInto(&out.DevfileRegistryRoute)
	if in.ExternalDevfileRegistries != nil {
		in, out := &in.ExternalDevfileRegistries, &out.ExternalDevfileRegistries
		*out = make([]ExternalDevfileRegistries, len(*in))
		copy(*out, *in)
	}
	in.PluginRegistryIngress.DeepCopyInto(&out.PluginRegistryIngress)
	in.PluginRegistryRoute.DeepCopyInto(&out.PluginRegistryRoute)
	if in.CustomCheProperties != nil {
		in, out := &in.CustomCheProperties, &out.CustomCheProperties
		*out = make(map[string]string, len(*in))
		for key, val := range *in {
			(*out)[key] = val
		}
	}
	if in.SingleHostGatewayConfigMapLabels != nil {
		in, out := &in.SingleHostGatewayConfigMapLabels, &out.SingleHostGatewayConfigMapLabels
		*out = make(labels.Set, len(*in))
		for key, val := range *in {
			(*out)[key] = val
		}
	}
	in.CheServerIngress.DeepCopyInto(&out.CheServerIngress)
	in.CheServerRoute.DeepCopyInto(&out.CheServerRoute)
	if in.WorkspacesDefaultPlugins != nil {
		in, out := &in.WorkspacesDefaultPlugins, &out.WorkspacesDefaultPlugins
		*out = make([]WorkspacesDefaultPlugins, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.WorkspacePodNodeSelector != nil {
		in, out := &in.WorkspacePodNodeSelector, &out.WorkspacePodNodeSelector
		*out = make(map[string]string, len(*in))
		for key, val := range *in {
			(*out)[key] = val
		}
	}
	if in.WorkspacePodTolerations != nil {
		in, out := &in.WorkspacePodTolerations, &out.WorkspacePodTolerations
		*out = make([]corev1.Toleration, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.WorkspaceDefaultComponents != nil {
		in, out := &in.WorkspaceDefaultComponents, &out.WorkspaceDefaultComponents
		*out = make([]v1alpha2.Component, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.CheServerEnv != nil {
		in, out := &in.CheServerEnv, &out.CheServerEnv
		*out = make([]corev1.EnvVar, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.DevfileRegistryEnv != nil {
		in, out := &in.DevfileRegistryEnv, &out.DevfileRegistryEnv
		*out = make([]corev1.EnvVar, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.PluginRegistryEnv != nil {
		in, out := &in.PluginRegistryEnv, &out.PluginRegistryEnv
		*out = make([]corev1.EnvVar, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.DashboardEnv != nil {
		in, out := &in.DashboardEnv, &out.DashboardEnv
		*out = make([]corev1.EnvVar, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.OpenVSXRegistryURL != nil {
		in, out := &in.OpenVSXRegistryURL, &out.OpenVSXRegistryURL
		*out = new(string)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CheClusterSpecServer.
func (in *CheClusterSpecServer) DeepCopy() *CheClusterSpecServer {
	if in == nil {
		return nil
	}
	out := new(CheClusterSpecServer)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CheClusterSpecStorage) DeepCopyInto(out *CheClusterSpecStorage) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CheClusterSpecStorage.
func (in *CheClusterSpecStorage) DeepCopy() *CheClusterSpecStorage {
	if in == nil {
		return nil
	}
	out := new(CheClusterSpecStorage)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CheClusterStatus) DeepCopyInto(out *CheClusterStatus) {
	*out = *in
	out.DevworkspaceStatus = in.DevworkspaceStatus
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CheClusterStatus.
func (in *CheClusterStatus) DeepCopy() *CheClusterStatus {
	if in == nil {
		return nil
	}
	out := new(CheClusterStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ExternalDevfileRegistries) DeepCopyInto(out *ExternalDevfileRegistries) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ExternalDevfileRegistries.
func (in *ExternalDevfileRegistries) DeepCopy() *ExternalDevfileRegistries {
	if in == nil {
		return nil
	}
	out := new(ExternalDevfileRegistries)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *GitHubService) DeepCopyInto(out *GitHubService) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new GitHubService.
func (in *GitHubService) DeepCopy() *GitHubService {
	if in == nil {
		return nil
	}
	out := new(GitHubService)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *GitLabService) DeepCopyInto(out *GitLabService) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new GitLabService.
func (in *GitLabService) DeepCopy() *GitLabService {
	if in == nil {
		return nil
	}
	out := new(GitLabService)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IngressCustomSettings) DeepCopyInto(out *IngressCustomSettings) {
	*out = *in
	if in.Annotations != nil {
		in, out := &in.Annotations, &out.Annotations
		*out = make(map[string]string, len(*in))
		for key, val := range *in {
			(*out)[key] = val
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IngressCustomSettings.
func (in *IngressCustomSettings) DeepCopy() *IngressCustomSettings {
	if in == nil {
		return nil
	}
	out := new(IngressCustomSettings)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *LegacyDevworkspaceStatus) DeepCopyInto(out *LegacyDevworkspaceStatus) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new LegacyDevworkspaceStatus.
func (in *LegacyDevworkspaceStatus) DeepCopy() *LegacyDevworkspaceStatus {
	if in == nil {
		return nil
	}
	out := new(LegacyDevworkspaceStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Resources) DeepCopyInto(out *Resources) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Resources.
func (in *Resources) DeepCopy() *Resources {
	if in == nil {
		return nil
	}
	out := new(Resources)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ResourcesCustomSettings) DeepCopyInto(out *ResourcesCustomSettings) {
	*out = *in
	out.Requests = in.Requests
	out.Limits = in.Limits
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ResourcesCustomSettings.
func (in *ResourcesCustomSettings) DeepCopy() *ResourcesCustomSettings {
	if in == nil {
		return nil
	}
	out := new(ResourcesCustomSettings)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *RouteCustomSettings) DeepCopyInto(out *RouteCustomSettings) {
	*out = *in
	if in.Annotations != nil {
		in, out := &in.Annotations, &out.Annotations
		*out = make(map[string]string, len(*in))
		for key, val := range *in {
			(*out)[key] = val
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new RouteCustomSettings.
func (in *RouteCustomSettings) DeepCopy() *RouteCustomSettings {
	if in == nil {
		return nil
	}
	out := new(RouteCustomSettings)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *WorkspacesDefaultPlugins) DeepCopyInto(out *WorkspacesDefaultPlugins) {
	*out = *in
	if in.Plugins != nil {
		in, out := &in.Plugins, &out.Plugins
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new WorkspacesDefaultPlugins.
func (in *WorkspacesDefaultPlugins) DeepCopy() *WorkspacesDefaultPlugins {
	if in == nil {
		return nil
	}
	out := new(WorkspacesDefaultPlugins)
	in.DeepCopyInto(out)
	return out
}
