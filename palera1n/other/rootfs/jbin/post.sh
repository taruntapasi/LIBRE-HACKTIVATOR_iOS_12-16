binpack=/jbin/binpack

$binpack/bin/rm -rf /var/.palera1n/loader.app
$binpack/usr/bin/uicache -p /jbin/loader.app

$binpack/usr/bin/killall -9 SpringBoard

echo "[post.sh] done"
exit
