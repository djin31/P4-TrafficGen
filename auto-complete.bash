OPTIONS_LIST="-h --help -p4 -json --std --only-headers -o --scapy --wireshark --moongen --pcpp --debug"

_p4_traffictool_completions()
{
	# keep the suggestions in a local variable
    CURR_WORD=${COMP_WORDS[COMP_CWORD]}

    if [[ $COMP_CWORD == 1 ]];  then
	        COMPREPLY=($(compgen -W  "${OPTIONS_LIST}" \""${COMP_WORDS[$COMP_CWORD]}"\"))
            LAST_WORD=$CURR_WORD
            return
    fi


    case $LAST_WORD in
        "-p")
            COMPREPLY=($(compgen -d -f \""${COMP_WORDS[$COMP_CWORD]}"\"))
            if [[ ( $CURR_WORD =~ "." ) || ( $CURR_WORD =~ "~"  ) || ( $CURR_WORD =~ "/" ) ]]; then
                file_entered=true
            fi

            if [[ ( $CURR_WORD == "" ) &&  ( $file_entered == true) ]]; then
                LAST_WORD=$CURR_WORD
                file_entered=false
            fi
		    ;;

	    *)
	        COMPREPLY=($(compgen -W  "${OPTIONS_LIST}" \""${COMP_WORDS[$COMP_CWORD]}"\"))
            LAST_WORD=$CURR_WORD
	        ;;
    esac
}

LAST_WORD=""
file_entered=false
complete -o filenames -o bashdefault -F _p4_traffictool_completions p4-traffictool
