# Rent tunnel token receiver (windows #14). place.ps1 -Target rent runs this text as the one bash -c argument of
#   wslc run --rm -i --volume windows-rent-state:/var/lib/rent <rent image by digest> /bin/bash -c <this text>
# using only the image's own bash and coreutils. It reads the token on stdin only and replaces the one slot that
# windows' rent-start checks: a regular file, owned 0:0, mode 600, 1 to 4096 bytes, not blank. An existing slot is
# replaced only while it is exactly that owned shape under parents only root can change; any other object is refused
# and left intact, and the same value changes nothing. It never prints the token. It holds no double quote or backslash, so it travels as one argument unchanged.
set -euo pipefail
umask 077
fail() { echo rent-receive: $* >&2; exit 2; }
# A parent only root can change: a real directory owned by uid 0 with no group or other write bit (rent-start lays the
# state root out 0:0 755; any such mode is accepted). Otherwise another user could redirect or replace the slot.
safe() { [ -d $1 ] && [ ! -L $1 ] && [ $(stat -c %u $1) = 0 ] && [ $(( 0$(stat -c %a $1) & 022 )) = 0 ]; }
state=/var/lib/rent
dir=$state/cloudflared
slot=$dir/token
safe $state || fail the state volume is not a root-owned directory only its owner can write
# One writer: the exclusive lock on the state root that rent-start, seed and state import take, held on fd 9 until
# exit. Busy (flock exit 75) and any other lock failure are refused apart, before anything is created or read.
exec 9<$state
/bin/flock -x -n -E 75 9 || { [ $? = 75 ] && fail the state volume is in use by a running rent or another writer; fail the state lock could not be taken; }
[ ! -L $dir ] || fail the slot directory is a link
[ -e $dir ] || mkdir $dir
safe $dir || fail the slot directory is not a root-owned directory only its owner can write
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
