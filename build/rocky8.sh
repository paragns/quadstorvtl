#!/bin/sh
set -x
sh buildinit.sh rocky8
cp -f quadstorcorerocky.spec quadstorcorerocky8.spec
cp -f quadstoritfrocky.spec quadstoritfrocky8.spec
sed -i -e "s/Release: .*/Release: rocky8/g" quadstorcorerocky8.spec
sed -i -e "s/Release: .*/Release: rocky8/g" quadstoritfrocky8.spec
sed -i -e "s/Rocky Linux X/Rocky Linux 8/g" quadstorcorerocky8.spec
sed -i -e "s/Rocky Linux X/Rocky Linux 8/g" quadstoritfrocky8.spec
rpmbuild -bb quadstorcorerocky8.spec && rpmbuild -bb quadstoritfrocky8.spec
