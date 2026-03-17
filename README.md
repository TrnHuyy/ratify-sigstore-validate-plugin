# How to add plugin into Ratify deployed in k8s cluster

## Create image

```bash
# Create binary file
GOOS=linux GOARCH=amd64 go build -o bundle-verifier

# Create image from binary file
docker build --platform linux/amd64  -t acrsandbox011.azurecr.io/ratify/bundle-verifier:v2.15 .
```

## Add plugin 

Create an initContainer in deployment/statefulset with following content:

```bash
initContainers:
- command:
- sh
- -c
- |
    mkdir -p /.ratify/plugins
    cp /bundle-verifier /.ratify/plugins/bundle-verifier
    chmod +x /.ratify/plugins/bundle-verifier
image: acrsandbox011.azurecr.io/ratify/bundle-verifier:v2.6
imagePullPolicy: IfNotPresent
name: install-plugin
resources: {}
terminationMessagePath: /dev/termination-log
terminationMessagePolicy: File
volumeMounts:
- mountPath: /.ratify/plugins
    name: plugins
```

