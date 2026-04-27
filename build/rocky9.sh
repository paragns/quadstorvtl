#!/bin/sh
set -x
sh buildinit.sh rocky9
cp -f quadstorcorerocky.spec quadstorcorerocky9.spec
cp -f quadstoritfrocky.spec quadstoritfrocky9.spec
sed -i -e "s/Release: .*/Release: rocky9/g" quadstorcorerocky9.spec
sed -i -e "s/Release: .*/Release: rocky9/g" quadstoritfrocky9.spec
sed -i -e "s/Rocky Linux X/Rocky Linux 9/g" quadstorcorerocky9.spec
sed -i -e "s/Rocky Linux X/Rocky Linux 9/g" quadstoritfrocky9.spec
rpmbuild -bb quadstorcorerocky9.spec && rpmbuild -bb quadstoritfrocky9.spec
