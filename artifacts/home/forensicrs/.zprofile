#!/bin/zsh

export GOPATH=$HOME/go

PATH=/usr/local/opt/ruby/bin:/usr/local/sbin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:/usr/X11/bin:$GOPATH/bin

CDPATH=.:~

export WORKON_HOME=~/virtualenvs
# sourcing virtualenvwrapper takes a second. that's too long when starting a new shell
alias venv='source /usr/local/bin/virtualenvwrapper.sh'
alias renv='source $HOME/.rvm/scripts/rvm' # Load RVM into a shell session *as a function*
alias ftc='venv && workon ftc'

source $HOME/.z_passwords

# Enable command not found support on Ubuntu
[[ -e /etc/zsh_command_not_found ]] && source /etc/zsh_command_not_found

export EDITOR="mate -w"
export GIT_EDITOR=$EDITOR
export SVN_EDITOR=$EDITOR

export JAVA_HOME=/usr

export CLICOLOR=1
export GREP_COLOR=auto
export LSCOLORS=Exgxcxdxbxegedabagacad
export WORDCHARS='*?[]~&;!$%^<>'

# Fix for xquartz
export DISPLAY=:0

HISTFILE=~/.zsh_history
HISTSIZE=50000
SAVEHIST=50000
setopt INC_APPEND_HISTORY EXTENDED_HISTORY HIST_IGNORE_DUPS

# Show hostname and working directory in window title format titles for screen and rxvt
function title() {
  # escape '%' chars in $1, make nonprintables visible
  a=${(V)1//\%/\%\%}

  # Truncate command and join lines.
  a=$(print -Pn "%40>...>$a" | tr -d "\n")

  if [ $a ]
  then
    a=" — $a"
  fi
  print -Pn "\e]2;$2:$3$a\a" # plain xterm title
}


# preexec is called just before any command line is executed
function preexec() {
  title "$1" "$USER@%m" "%35<...<%~"
}
# precmd is called just before the prompt is printed
function precmd () {
  title "" "$USER@%m" "%55<...<%~"
}

# Enable Rupa's Z
. ~/bin/z.sh

GREEN_START=$'\e[32m'
WHITE_START=$'\e[0m'
YELLOW_START=$'\e[33m'
BLUE_START=$'\e[36m'
PS1="%{${GREEN_START}%}%n%{${WHITE_START}%}@%{${YELLOW_START}%}%m%{${WHITE_START}%}:%{${BLUE_START}%}%~%{${WHITE_START}%}%# "

# colorful listings
zmodload -i zsh/complist
zstyle ':completion:*' list-colors ${(s.:.)LSCOLORS}

zstyle ':completion:*:*:kill:*' menu yes select
zstyle ':completion:*:kill:*'   force-list always

# tab-completion for stuff
autoload -U compinit
compinit
# don't use autocompletion for git. it's slow as hell
compdef -d git

alias mv='nocorrect mv'
alias cp='nocorrect cp'
alias mkdir='nocorrect mkdir'

#alias ls='ls -F --color=auto'
alias ls='ls -GF'
alias no='ls -a'
alias na='ls -la'
alias ll='ls -la'
alias non='ls -halt'
alias cd..='cd ..'
alias ..='cd ..'

#alias lock='/System/Library/CoreServices/"Menu Extras"/User.menu/Contents/Resources/CGSession -suspend'
alias lock='gnome-screensaver-command -l'
alias op='xdg-open'

# Get fn+delete working in zsh
bindkey "^[[3~" delete-char

autoload edit-command-line
zle -N edit-command-line
bindkey '^X^e' edit-command-line

rot13 () { tr "[a-m][n-z][A-M][N-Z]" "[n-z][a-m][N-Z][A-M]" }

function git-rm-untracked {
    git st -s -u | awk "{ print \$2 }" | xargs rm
}

function svtail {
    tail -F /service/$@/log/main/current
}

function svtailall {
    tail -F /service/*/log/main/current
}

function git_current_branch() {
    git symbolic-ref HEAD 2> /dev/null | sed -e 's/refs\/heads\///'
}

function git_current_origin() {
    git config --get remote.origin.url | sed -e 's/^.*\://' | sed -e 's/\.git.*//'
}

# create a github pull request from the current branch
alias gpr='open "https://github.com/$(git_current_origin)/pull/new/$(git_current_branch)"'

# Show manpage in textmate
function tman {
    MANWIDTH=100 MANPAGER='col -bx' man $@ | mate
}

# Function for making PDF versions of man pages
function pman() {
    man $@ -t | open -f -a Preview
}

# usage: "multi 3 echo blah" will print blah 3 times
function multi {
    n=$1; shift; for ((i=0;i<n;i++)) do $@; done;
}