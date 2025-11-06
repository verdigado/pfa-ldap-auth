#!/bin/bash

bash -c "go get ."
bash -c "go build ."
export TAG=$(echo $2 | sed "s/refs\/tags\///")
export VERSION=$(echo $2 | sed "s/refs\/tags\/v//")
echo "Creating release for version $VERSION (tag $TAG)"
export RESPONSE=$(curl -L -X POST -H "Accept: application/vnd.github+json" -H "Authorization: Bearer $1" -H "X-GitHub-Api-Version: 2022-11-28" https://api.github.com/repos/verdigado/pfa-ldap-auth/releases -d "{\"tag_name\":\"$TAG\",\"target_commitish\":\"main\",\"name\":\"$TAG\",\"body\":\"Version $VERSION\",\"draft\":false,\"prerelease\":false,\"generate_release_notes\":false}")
echo "$RESPONSE"
export RELEASE_ID=$(echo "$RESPONSE" | jq .id)
echo "Attaching file to release $RELEASE_ID"
echo "Build for x86_64:"
ls -lah pfa-ldap-auth
curl -L -X POST -H "Accept: application/vnd.github+json" -H "Authorization: Bearer $1" -H "Content-Type: application/octet-stream" --data-binary @"pfa-ldap-auth" "https://uploads.github.com/repos/verdigado/pfa-ldap-auth/releases/$RELEASE_ID/assets?name=pfa-ldap-auth"
echo "Finished: $?"