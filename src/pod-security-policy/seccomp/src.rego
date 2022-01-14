package k8spspseccomp

allowed_annotation_key = "seccomp.security.alpha.kubernetes.io/allowedProfileNames"
container_annotation_key_prefix = "container.seccomp.security.alpha.kubernetes.io/"
default_annotation_key = "seccomp.security.alpha.kubernetes.io/defaultProfileName"
pod_annotation_key = "seccomp.security.alpha.kubernetes.io/pod"

violation[{"msg": msg, "details": {}}] {
    not input_wildcard_allowed
    container := input_containers[_]
    not input_container_allowed(container)
    not input_pod_allowed
    msg := sprintf("Seccomp profile is not allowed, pod: %v, container: %v, Allowed profiles: %v", [input.review.object.metadata.name, container.name, input.parameters.allowedProfiles])
}

input_wildcard_allowed {
    input.parameters.allowedProfiles[_] == "*"
}

input_pod_allowed {
  input.review.object.metadata.annotations[default_annotation_key] == input.parameters.allowedProfiles[_]
}

input_pod_allowed {
  input.review.object.metadata.annotations[pod_annotation_key] == input.parameters.allowedProfiles[_]
}

input_pod_allowed {
  input.review.object.spec.securityContext.seccompProfile.type == input.parameters.allowedProfiles[_]
}

input_container_allowed(container) {
	profile := get_container_profile(container)
	profile == input.parameters.allowedProfiles[_]
}

# Containers profile as defined in annotations
get_container_profile(container) = profile {
	value := input.review.object.metadata.annotations[key]
  startswith(key, container_annotation_key_prefix)
  [prefix, name] := split(key, "/")
  name == container.name
  profile = value
}

get_container_profile(container) = profile {
  annotations := input.review.object.metadata.annotations
  annotations[key]
  startswith(key, container_annotation_key_prefix)
  [prefix, name] := split(key, "/")
  name != container.name
  profile = annotations[pod_annotation_key]
}

# Containers profile as defined in securityContext
get_container_profile(container) = profile {
  profile = container.securityContext.seccompProfile.type
}

input_containers[c] {
    c := input.review.object.spec.containers[_]
}
input_containers[c] {
    c := input.review.object.spec.initContainers[_]
}
