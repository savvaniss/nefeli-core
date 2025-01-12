# Script gets votes for a block range.
# Run: perl votes.pl 60 300

$IP='127.0.0.1:11181';

$begin=$ARGV[0];
if ($#ARGV == 1 ) { $end=$ARGV[1]; }

open (F,">vote.txt");
for ($i=$begin; $i<$end; $i++) {
    $k=qq(-d '{"params":{"height":$i},"jsonrpc":"2.0","id":"test","method":"get_block_header_by_height"}' -H 'Content-Type: application/json');
    $k=`curl -s -X POST http://$IP/json_rpc $k`;
    $k=~/"vote"\D+(\d+)/sg;
    $v=$1;
    print F "$v ";
}
close F;

$s = do{local(@ARGV,$/)="vote.txt";<>};
$yes = "1";
$count1 = () = $s =~ /\Q$yes/g;
print "$count1 votes for yes\n";
$no = "2";
$count2 = () = $s =~ /\Q$no/g;
print "$count2 votes for no\n";
$abs = "0";
$count0 = () = $s =~ /\Q$abs/g;
print "$count0 abstained\n";

if ($count1 > $count2) {
    print "Computer says... Yes!\n";
} else {
    print "Computer says... No!\n";
}