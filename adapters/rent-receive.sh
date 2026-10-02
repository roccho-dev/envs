# Rent tunnel token receiver (windows #14). place.ps1 -Target rent runs this text as the one bash -c argument of
#   wslc run --rm -i --volume windows-rent-state:/var/lib/rent <rent image by digest> /bin/bash -c <this text>
# using only the image's own bash and coreutils. It reads the token on stdin only and replaces the one slot that
# windows' rent-start checks: a regular file, owned 0:0, mode 600, 1 to 4096 bytes, not blank. An existing slot is
# replaced only while it is exactly that owned shape; any other object is refused and left intact, and the same value
# changes nothing. It never prints the token. It holds no quote or backslash, so it travels as one argument unchanged.
set -euo pipefail
umask 077
fail() { echo rent-receive: $* >&2; exit 2; }
state=/var/lib/rent
dir=$state/cloudflared
slot=$dir/token
[ -d $state ] && [ ! -L $state ] || fail the state volume is absent
[ ! -L $dir ] || fail the slot directory is a link
mkdir -p $dir
[ -d $dir ] || fail the slot directory is not a directory
[ ! -L $slot ] || fail the slot is a link
[ ! -e $slot ] || [ -f $slot ] || fail the slot is not a regular file
[ ! -e $slot ] || [ $(stat -c %u:%g:%a $slot) = 0:0:600 ] || fail the slot is not the owned 0:0 600 token
temp=$(mktemp $dir/.token.XXXXXXXX)
trap 'rm -f -- $temp' EXIT
head -c 4097 >$temp
size=$(stat -c %s $temp)
[ $size -ge 1 ] && [ $size -le 4096 ] || fail the token is not 1 to 4096 bytes
grep -q '[^[:space:]]' $temp || fail the token is blank
if [ -e $slot ] && cmp -s $temp $slot; then
  echo rent-receive: unchanged
  exit 0
fi
chown 0:0 $temp
chmod 600 $temp
mv -f -- $temp $slot
trap - EXIT
echo rent-receive: placed
