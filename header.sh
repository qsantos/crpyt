#!/bin/bash
for i in $(find -name "*.py")
do
	exec > tmp

	# new header (end of this script)
	tail -n18 $0

	# length of the old header
	line=`grep -Enm1 '^# END LICENCE$' $i`
	line=${line%%:*}
	line=${line:--1}
	line=$(($line+2))

	# skip the old header
	tail "$i" "-n+$line"

	mv tmp $i
done
exit 0
# crpyt: toy cryptographic python library
# Copyright (C) 2014 Quentin SANTOS
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# END LICENCE

