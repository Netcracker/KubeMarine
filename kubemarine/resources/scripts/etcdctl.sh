#!/bin/bash

if [[ $EUID -ne 0 ]]; then
   echo "Root access required"
   exit 1
fi

if systemctl is-active --quiet docker; then
  CONT_RUNTIME="docker"
elif ctr --version &> /dev/null; then
  CONT_RUNTIME="ctr"
else
  echo "Neither ctr nor docker are available to run container, exiting with error..."
fi

# Try to read pod yaml from kubernetes
ETCD_POD_NAME=$(kubectl get pods -n kube-system | tac | grep Running | grep '1/1' | grep etcd | awk '{print $1; exit}')
if [ -n "${ETCD_POD_NAME}" ] && [ "$?" -eq '0' ]; then
  ETCD_POD_CONFIG=$(kubectl get pod "${ETCD_POD_NAME}" -n kube-system -o yaml)
fi

# If failed to get configuration from kubernetes
if [ -z "${ETCD_POD_CONFIG}" ] || [ "$?" -ne '0' ]; then
  # Try to read pod yaml config from local dir
  if [ -f "/etc/kubernetes/manifests/etcd.yaml" ]; then
    ETCD_POD_CONFIG=$(cat /etc/kubernetes/manifests/etcd.yaml)
  else
    echo "Unable to find etcd configuration neither in kubernetes nor on host, exiting with error..."
    exit 1
  fi
fi

# If any pod configuration detected
if [ -n "${ETCD_POD_CONFIG}" ]; then
  ETCD_IMAGE=$(echo "${ETCD_POD_CONFIG}" | grep ' image:' | awk '{print $2; exit}')
  ETCD_MOUNTS=""
  ETCD_MOUNTS_RAW=$(echo "${ETCD_POD_CONFIG}" | grep ' mountPath: ')
  ETCD_CERT=$(echo "${ETCD_POD_CONFIG}" | grep '\- --cert-file' | sed s/=/\\n/g | sed -n 2p)
  ETCD_KEY=$(echo "${ETCD_POD_CONFIG}" | grep '\- --key-file' | sed s/=/\\n/g | sed -n 2p)
  ETCD_CA=$(echo "${ETCD_POD_CONFIG}" | grep '\- --trusted-ca-file' | sed s/=/\\n/g | sed -n 2p)
  ETCD_ENDPOINTS=$(echo "${ETCD_POD_CONFIG}" | grep '\- --initial-cluster=' | sed -e 's/\s*- --initial-cluster=//g' -e "s/[a-zA-Z0-9\.-]*=//g" -e "s/2380/2379/g")
  while IFS= read -r line; do
      volume=$(echo "${line}" | awk '{print $3; exit}')
      if [ "$CONT_RUNTIME" == "ctr" ]; then
        ETCD_MOUNTS="${ETCD_MOUNTS} -mount type=bind,src=${volume},dst=${volume},options=rbind:rw"
      else
        ETCD_MOUNTS="${ETCD_MOUNTS} -v ${volume}:${volume}"
      fi
  done <<< "${ETCD_MOUNTS_RAW}"

  # User can override some of our "default" etcdctl args (see cases).
  # If user passed his own arg, then our "default" arg will be NULLed.
  USER_ARGS=("$@")
  opts=$(getopt --quiet --longoptions "endpoints:," -- "$@")
  eval set --$opts
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --endpoints)
        ETCD_ENDPOINTS=""
        shift 2
        ;;
      *)
        # skip unknown options
        shift 1
        ;;
    esac
  done
  # If our default arg is not NULLed, then user did not provided his own flag and we should append our default.
  # Otherwise arg is already provided by user and thus our default arg should not be appended.
  if [ -n "$ETCD_ENDPOINTS" ]; then
    USER_ARGS+=("--endpoints=$ETCD_ENDPOINTS")
  fi

  if [ "$CONT_RUNTIME" == "ctr" ]; then
    ETCD_REGISTRY=$(echo ${ETCD_IMAGE} | cut -d "/" -f1)
    ctr_default_pull_opts=$(cat /etc/ctr/kubemarine_ctr_flags.conf |  grep "^*=" | sed "s/^*=//;")
    ctr_pull_opts=$(cat /etc/ctr/kubemarine_ctr_flags.conf |  grep "^${ETCD_REGISTRY}=" | sed "s/^${ETCD_REGISTRY}=//;")
    container_name="etcdctl-$(cat /proc/sys/kernel/random/uuid | sed 's/[-]//g' | head -c 20; echo;)"
    ctr image pull ${ctr_default_pull_opts} ${ctr_pull_opts} ${ETCD_IMAGE} > /dev/null 2&>1
    ctr run --net-host --rm ${ETCD_MOUNTS} --env ETCDCTL_API=3 ${ETCD_IMAGE} $container_name \
	    etcdctl --cert=${ETCD_CERT} --key=${ETCD_KEY} --cacert=${ETCD_CA} "${USER_ARGS[@]}"
  else
    docker run --rm ${ETCD_MOUNTS} -e ETCDCTL_API=3 ${ETCD_IMAGE} \
	    etcdctl --cert=${ETCD_CERT} --key=${ETCD_KEY} --cacert=${ETCD_CA} "${USER_ARGS[@]}"
  fi
  exit $?
fi
