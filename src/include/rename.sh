#!/bin/bash

for file in `find . -name 'my_*.h' -type f -maxdepth 1`
do
	new=${file#./my_*}
	echo "new: ${new}"
	git mv ${file} ${new}
done
