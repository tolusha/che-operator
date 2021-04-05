//
// Copyright (c) 2021 Red Hat, Inc.
// This program and the accompanying materials are made
// available under the terms of the Eclipse Public License 2.0
// which is available at https://www.eclipse.org/legal/epl-2.0/
//
// SPDX-License-Identifier: EPL-2.0
//
// Contributors:
//   Red Hat, Inc. - initial API and implementation
//

// Important: Run "operator-sdk generate k8s" and "operator-sdk generate crds" to regenerate code after modifying this file

package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +k8s:openapi-gen=true
// CheClusterBackupSpec defines the desired state of CheClusterBackup
type CheClusterBackupSpec struct {
	// Automatically setup container with REST backup server and use the server in this configuration.
	// Note, this will overwrite existing configuration.
	AutoconfigureRestBackupServer bool `json:"autoconfigureRestBackupServer,omitempty"`
	// Set to true to start backup process.
	TriggerNow bool `json:"triggerNow,omitempty"`
	// If more than one backup server configured, should specify which one to use.
	// Allowed values are fields names form BackupServers struct.
	ServerType string `json:"serverType,omitempty"`
	// List of backup servers.
	// Usually only one is used.
	// In case of several available, ServerType should contain server to use.
	Servers BackupServers `json:"servers"`
}

// +k8s:openapi-gen=true
// List of supported backup servers
type BackupServers struct {
	// Rest server within the cluster.
	// The server and configuration are created by operator when AutoconfigureRestBackupServer is true
	Internal RestServerConfing `json:"internal,omitempty"`
	// Sftp backup server configuration
	Sftp SftpServerConfing `json:"sftp,omitempty"`
	// Rest backup server configuration
	Rest RestServerConfing `json:"rest,omitempty"`
	// Amazon S3
	AwsS3 AwsS3ServerConfig `json:"awss3,omitempty"`
	// Minio server
	Minio AwsS3ServerConfig `json:"minio,omitempty"`
}

// Holds restic repository password to decrypt its content
type RepoPassword struct {
	// Password for restic repository
	RepoPassword string `json:"repoPassword,omitempty"`
	// Secret with 'repo-password' filed
	RepoPasswordSecretRef string `json:"repoPasswordSecretRef,omitempty"`
}

// +k8s:openapi-gen=true
// SFTP backup server configuration
// Example: user@host://srv/repo
type SftpServerConfing struct {
	RepoPassword `json:"repoPassword"`
	// Backup server host
	Hostname string `json:"hostname"`
	// Backup server port
	Port string `json:"port,omitempty"`
	// Restic repository path
	Repo string `json:"repo"`
	// User login on the remote server
	Username string `json:"username"`
	// Private ssh key for passwordless login
	SshKeySecretRef string `json:"sshKeySecretRef"`
}

// +k8s:openapi-gen=true
// REST backup server configuration
// Example: https://user:password@host:5000/repo/
type RestServerConfing struct {
	RepoPassword `json:"repoPassword"`
	// Protocol to use when connection to the server
	// Defaults to https.
	Protocol string `json:"protocol,omitempty"`
	// Backup server host
	Hostname string `json:"hostname"`
	// Backup server port
	Port string `json:"port,omitempty"`
	// Restic repository path
	Repo string `json:"repo,omitempty"`
	// User login on the remote server
	Username string `json:"username,omitempty"`
	// Password to authenticate the user
	Password string `json:"password,omitempty"`
	// Secret that contains username and password fields
	CredentialsSecretRef string `json:"credentialsSecretRef,omitempty"`
}

// +k8s:openapi-gen=true
type AwsS3ServerConfig struct {
	RepoPassword `json:"repoPassword"`
	// Server hostname, defaults to 's3.amazonaws.com'.
	// For Amazon alternatives should include protocal, e.g. 'http://host:port'
	Hostname string `json:"hostname,omitempty"`
	// Bucket name. If doesn' exist, it will be created automatically.
	BucketName string `json:"bucketName,omitempty"`
	// Content of AWS_ACCESS_KEY_ID environment variable
	AwsAccessKeyId string `json:"awsAccessKeyId,omitempty"`
	// Content of AWS_SECRET_ACCESS_KEY environment variable
	AwsSecretAccessKey string `json:"awsSecretAccessKey,omitempty"`
	// Reference to secret that contains AWS_SECRET_ACCESS_KEY and AWS_ACCESS_KEY_ID fields
	AwsAccessKeySecretRef string `json:"awsAccessKeySecretRef,omitempty"`
	// Region used by default.
	// Empty value means automatic selection by remote server.
	AwsDefaultRegion string `json:"awsDefaultRegion,omitempty"`
}

// +k8s:openapi-gen=true
// CheClusterBackupStatus defines the observed state of CheClusterBackup
type CheClusterBackupStatus struct {
	// Backup result or error message
	Message string `json:"message,omitempty"`
	// Shows when backup was triggered last time
	LastTriggered string `json:"lastTriggered,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// CheClusterBackup is the Schema for the checlusterbackups API
// +kubebuilder:subresource:status
// +kubebuilder:resource:path=checlusterbackups,scope=Namespaced
type CheClusterBackup struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   CheClusterBackupSpec   `json:"spec,omitempty"`
	Status CheClusterBackupStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// CheClusterBackupList contains a list of CheClusterBackup
type CheClusterBackupList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []CheClusterBackup `json:"items"`
}

func init() {
	SchemeBuilder.Register(&CheClusterBackup{}, &CheClusterBackupList{})
}