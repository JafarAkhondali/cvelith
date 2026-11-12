#!/bin/bash
BASEPATH=$(pwd)/cve/tmpstorage/epss-data
mkdir -p $BASEPATH
cd $BASEPATH
CORES=$(nproc)
THREADS=$((CORES * 2))

# Temporary directory for intermediate files
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT  # Ensure cleanup of temp files on script exit

# Combined output file
COMBINED_FILE="$BASEPATH/epss_combined.csv"
echo "cve,epss,date" > "$COMBINED_FILE"

function download_season {
    local STARTDATE=$1
    local ENDDATE=$2
    local SEASON=$3

    mkdir -p "$BASEPATH/$SEASON"
    cd "$BASEPATH/$SEASON"

    dates=$(seq $(date -d "$STARTDATE" +%s) 86400 $(date -d "$ENDDATE" +%s) | \
        xargs -I {} date -I -d @{})

    function download_data {
        CURRENTDATE=$1
        echo "Downloading data for: $CURRENTDATE"
        wget -q -nc https://epss.empiricalsecurity.com/epss_scores-$CURRENTDATE.csv.gz
    }

    export -f download_data
    echo "$dates" | parallel --jobs "$THREADS" download_data {}

    cd "$BASEPATH"
}

function process_file {
    SEASON=$1
    FILE=$2
    TEMP_DIR=$3

    FILEDATE=$(basename "$FILE" | grep -oP '\d{4}-\d{2}-\d{2}')  # Extract clean date
    TEMP_FILE="$TEMP_DIR/$(basename "$FILE" .gz).tmp"

    echo "Processing file: $FILE in season: $SEASON"

    gunzip -c "$FILE" | {
        if [ "$SEASON" == "3rd" ] || [ "$SEASON" == "4th" ]; then
            sed '1,2d' | awk -F',' -v date="$FILEDATE" '{print $1 "," $2 "," date}'
        else
            sed '1d' | awk -F',' -v date="$FILEDATE" '{print $1 "," $2 "," date}'
        fi
    } > "$TEMP_FILE"
}

# Download data for each season
#download_season "2021-04-14" "2021-09-01" "1st"
#download_season "2021-09-01" "2022-02-04" "2nd"
#download_season "2025-03-10" "$(date '+%Y-%m-%d')" "3rd"
#download_season "2025-07-10" "$(date '+%Y-%m-%d')" "4th"
#download_season "2025-03-17" "2025-07-27" "4th"
download_season "2023-03-09" "2025-03-14" "4th"
download_season "2025-03-16" "2026-02-11" "4th"


export -f process_file

# Process data for each season
for SEASON in "4th"; do
#for SEASON in "1st" "2nd" "3rd"; do
    DIR="$BASEPATH/$SEASON"
    if [ -d "$DIR" ]; then
        echo "Processing $SEASON season..."
        cd "$DIR" || exit
        find . -name "*.gz" | parallel --jobs "$CORES" process_file "$SEASON" {} "$TEMP_DIR"
    else
        echo "...$SEASON directory does not exist."
    fi

done

# Combine all temporary files into the final output
cat "$TEMP_DIR"/*.tmp >> "$COMBINED_FILE"
echo "Done!"
