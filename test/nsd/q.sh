#!/bin/sh

# query NSD and put the answers
# in a file.

ANSWERS=answers.nsd.test.$$
DIFF=diff.test.$$
PORT=$1         # given by makefile
DIG="dig -p $PORT @localhost"
SEP="======================================="

# clear
echo $SEP > $ANSWERS

# fire of the questions
# ; and # count as comments in questions file
cat questions | sed -e "/^;/d" | sed -e "/^#/d" |
while read i; do
        # da question (all oneliners)
        echo Q:$DIG $i >> $ANSWERS
        # da answer
        echo A: >> $ANSWERS
        # nuke the ID, and remove some other stuff
        # this can probably done more efficient....
        $DIG $i | sed -e "/^$/d" | sed -e "/;; glo/d" \
                | sed -e "s/id: .*/id: XXXXX/" \
                | sed -e "/; <<>>/d" | sed -e "/;; Got/d" \
                | sed -e "/;; SERVER/d" | sed -e "/;; Query/d" \
                | sed -e "/;; MSG/d" | sed -e "/;; WHEN/d" >> $ANSWERS

        # nice separator
        echo $SEP >> $ANSWERS
done
echo
echo "Created:       $ANSWERS."
echo -n "Creating diff: "
diff correct_answers $ANSWERS > $DIFF
echo "$DIFF"
if [ ! -s $DIFF ]; then
        echo "Diff is empty - everything is OK"
        echo "removing $DIFF"
        echo
        rm -f $DIFF
else
        echo "Diff is not empty"
        echo "send it to nsd-bugs@nlnetlabs.nl"
        echo
fi
