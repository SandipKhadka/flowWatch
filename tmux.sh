SESSION="my ids"

tmux has-session -s $SESSION

if $?!=0; then
    tmux new-session -s $SESSION
    tmux new-window -
fi
