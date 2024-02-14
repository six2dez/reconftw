SCRIPTPATH="$(
	cd "$(dirname "$0")" >/dev/null 2>&1 || exit
	pwd -P
)"

echo $SCRIPTPATH
