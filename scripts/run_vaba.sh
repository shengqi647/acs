n="$1"
bc="$2"
b="$3"
x=$((n - 1))
for i in $(seq 0 $x); do
  tmux new -s s$i -d
  tmux send-keys -t s$i "python scripts/vaba_run.py -f conf/adkg_$n/local.$i.json -time 1 -d  > out/out$i" C-m
done
