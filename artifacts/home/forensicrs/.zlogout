#!/usr/bin/zsh
ls -l > /tmp/t1    
xterm_cnt=$( ps -fu $USER | grep -v grep | grep -wc zsh )
if (( ${xterm_cnt} <= 1 )) ; then
    pkill -U ${USER} kicker
fi