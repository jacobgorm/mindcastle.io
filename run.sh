echo umount
su -c 'umount -f /mnt'

echo pkill
su -c 'pkill -9 oneroot'

echo rmmod
su -c 'rmmod nbd && modprobe nbd' || exit 1

echo cleanup state
su -c 'rm -rf cache/* swapdata-*'

su -c './build/oneroot arch.swap'
