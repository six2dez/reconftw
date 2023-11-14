#!/usr/bin/env bash 

declare __spinny__spinner_pid

declare -a __spinny__frames=()

spinny::start() {
  tput civis
  spinny::_spinner &
  __spinny__spinner_pid=$!
}

spinny::stop() {
  [[ -z "$__spinny__spinner_pid" ]] && return 0

  kill -9 "$__spinny__spinner_pid" 
  # Use conditional to avoid exiting the program immediatly
  wait "$__spinny__spinner_pid" 2>/dev/null || true
}

spinny::_spinner() {
  local delay=${SPINNY_DELAY:-0.3}
  spinny::_load_frames
  spinny::_pad_frames
  while :
  do
    for frame in "${__spinny__frames[@]}"
    do
      # After rendering each frame the cursor is reset to 
      # the previous position so that the next frame can 
      # overwrite it
      tput sc
      printf "%b" "$frame"
      tput rc
      sleep "$delay"
    done
  done
}

spinny::_pad_frames() {
  # Frames with different lengths need to be padded
  # for a smooth animation. We calculate the maximum
  # size of all frames and pad all smaller ones with
  # white space.
  local max_length
  max_length=$(spinny::_max_framelength)
  local array_length=${#__spinny__frames[@]}
  for (( i=0; c<array_length; c++ )) do
    local frame=${__spinny__frames[i]}
    local frame_length=${#frame}
    diff=$((max_length - frame_length + 1))
    # This adds the required number of white spaces
    # to the frame
    # TODO: Replace with pure bash if possible
    filler=$(seq -s ' ' "$diff" |tr -d '[:digit:]')
    __spinny__frames[i]="$frame$filler"
  done
}

spinny::_max_framelength() {
  local max=${#__spinny__frames[0]}
  for frame in "${__spinny__frames[@]}"
  do
    local len=${#frame}
    ((len > max)) && max=$len
  done
  echo "$max"
}

spinny::_load_frames() {
  # Load custom frames if any or fall back on the default animation
  if [[ -z $SPINNY_FRAMES ]]; then 
    __spinny__frames=(- "\\" "|" /)
  else
    __spinny__frames=("${SPINNY_FRAMES[@]}")
  fi
}

spinny::_finish(){
  # Make sure to remove variables and make the cursor visible again
  unset __spinny__spinner_pid
  unset __spinny__frames
  tput cnorm
}

trap spinny::_finish EXIT


