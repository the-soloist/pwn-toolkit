#!/bin/sh

if [ $# -lt 1 ]; then
	echo "Usage: $0 [commit message]"
	echo " e.g.: $0 update..."
	exit 1
fi

COMMIT=$*
echo $COMMITl

set -x

# update requirements.txt
# TMP_PYREQ_PATH="/tmp/.temp-requirements.txt"
# pipreqs . --use-local --print --mode compat >$TMP_PYREQ_PATH && cat $TMP_PYREQ_PATH | sort > ./requirements.txt && rm $TMP_PYREQ_PATH
pipreqs . --use-local --mode compat --force

# push repo
git add .
git commit -m "$COMMIT"
git push
# git push origin --tags
# git push --force origin main
