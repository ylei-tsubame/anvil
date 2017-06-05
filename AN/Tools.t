#!/usr/bin/perl
 
use strict;
use warnings;
use POSIX;
use Data::Dumper;
use utf8;

# Be nice and set a version number.
our $VERSION="3.0.0";
 
# Call in the test module, telling it how many tests to expect to run.
use Test::More tests => 39;

# Load my module via 'use_ok' test.
BEGIN
{
	print "Beginning tests of the AN::Tools suite of modules.\n";
	use_ok('AN::Tools', 3.0.0);
}

### Core tests
my $an = AN::Tools->new();
like($an, qr/^AN::Tools=HASH\(0x\w+\)$/, "Verifying that AN::Tools object is valid.");
like($an->data, qr/^HASH\(0x\w+\)$/, "Verifying that '\$an->data' is a hash reference.");
is($an->environment, "cli", "Verifying that \$an->environment initially reports 'cli'.");
$an->environment('html');
is($an->environment, "html", "Verifying that \$an->environment was properly set to 'html'.");
$an->environment('cli');
is($an->environment, "cli", "Verifying that \$an->environment was properly reset back to 'cli'.");

# Test handles to child modules.
like($an->Alert, qr/^AN::Tools::Alert=HASH\(0x\w+\)$/, "Verifying that '\$an->Alert' is a handle to AN::Tools::Alert.");
like($an->Storage, qr/^AN::Tools::Storage=HASH\(0x\w+\)$/, "Verifying that '\$an->Alert' is a handle to AN::Tools::Storage.");
like($an->Words, qr/^AN::Tools::Words=HASH\(0x\w+\)$/, "Verifying that '\$an->Alert' is a handle to AN::Tools::Words.");

### AN::Tools::Storage methods
# Search directory tests
my $array1   = $an->Storage->search_directories;
my $a1_count = @{$array1};
cmp_ok($a1_count, '>', 0, "Verifying that \$an->Storage->search_directories has at least one entry. Found: [$a1_count] directories.");

$an->Storage->search_directories({directories => "/root,/usr/bin,/some/fake/directory"});
my $array2   = $an->Storage->search_directories;
my $a2_count = @{$array2};
cmp_ok($a2_count, '==', 2, "Verifying that \$an->Storage->search_directories now has 2 entries from a passed in CSV, testing that the list changed and a fake directory was dropped.");

$an->Storage->search_directories({directories => ["/usr/bin", "/tmp", "/home"] });
my $array3   = $an->Storage->search_directories;
my $a3_count = @{$array3};
cmp_ok($a3_count, '==', 3, "Verifying that \$an->Storage->search_directories now has 3 entries from a passed in array reference, verifying that the list changed again.");

$an->Storage->search_directories({directories => "invalid" });
my $array4   = $an->Storage->search_directories;
my $a4_count = @{$array4};
cmp_ok($a4_count, '==', $a1_count, "Verifying that \$an->Storage->search_directories has the original number of directories: [$a4_count] after being called with an invalid 'directories' parameter, showing that it reset properly.");

my $test_path = $an->Storage->find({ file => "AN/Tools.t" });
is($test_path, "/usr/share/perl5/AN/Tools.t", "Verifying that \$an->Storage->find successfully found 'AN/Tools.t'.");
my $bad_path  = $an->Storage->find({ file => "AN/wa.t" });
is($bad_path, "#!not_found!#", "Verifying that \$an->Storage->find properly returned '#!not_found!#' for a non-existed file.");

# Config file read tests.
$an->data->{foo}{bar}{a} = "test";
is($an->Storage->read_config({ file => "AN/test.conf" }), 0, "Verifying that '\$an->Storage->read_config' successfully found 'AN/test.conf'.");
is($an->Storage->read_config({ file => "" }), 1, "Verifying that '\$an->Storage->read_config' returns '1' when called without a 'file' parameter being set.");
is($an->Storage->read_config({ file => "AN/moo.conf" }), 2, "Verifying that '\$an->Storage->read_config' returns '2' when the non-existent 'AN/moo.conf' is passed.");
cmp_ok($an->data->{foo}{bar}{a}, 'eq', 'I am "a"', "Verifying that 'AN/test.conf's 'foo::bar::a' overwrote an earlier set value.");
cmp_ok($an->data->{foo}{bar}{b}, 'eq', 'I am "b", split with tabs and having trailing spaces.', "Verifying that 'AN/test.conf's 'foo::bar::b' has whitespaces removed as expected.");
cmp_ok($an->data->{foo}{baz}{1}, 'eq', 'This is \'1\' with no spaces', "Verifying that 'AN/test.conf's 'foo::baz::1' parsed without spaces around '='.");
cmp_ok($an->data->{foo}{baz}{2}, 'eq', 'I had a $dollar = sign and split with tabs.', "Verifying that 'AN/test.conf's 'foo::baz::2' had no trouble with a '\$' and '=' characters in the string.");

### AN::Tools::Words methods
# Make sure we can read words files
is($an->Words->read({file => $an->data->{path}{words}{'an-tools.xml'}}), 0, "Verifying that '\$an->Words->read' properly returned '0' when asked to read the AN::Tools's words file.");
is($an->Words->read({file => ''}), 1, "Verifying that '\$an->Words->read' properly returned '1' when asked to read a works file without a file being passed.");
is($an->Words->read({file => '/tmp/dummy.xml'}), 2, "Verifying that '\$an->Words->read' properly returned '2' when asked to read a non-existent file.");
### NOTE: At this time, we don't test for unreadable files (rc = 3) or general read faults as set by XML::Simple (rc = 4).

# Make sure we can read raw strings.
is($an->Words->key({key => 't_0001'}), "Test replace: [#!variable!test!#].", "Verifying that '\$an->Words->key' returned the Canadian English 't_0001' string.");
is($an->Words->key({key => 't_0001', language => 'jp'}), "テスト いれかえる: [#!variable!test!#]。", "Verifying that '\$an->Words->read' returned the Japanese 't_0001' string.");
is($an->Words->key({key => 't_0003', language => 'jp'}), "#!not_found!#", "Verifying that '\$an->Words->read' returned '#!not_found!#' for the missing 't_0003' key.");

# Make sure we can read processed strings.
is($an->Words->string({
	key       => 't_0005',
	variables => {
		test   => "result!",
		first  => "1st",
		second => "2nd",
 	},
}), "
This is a multi-line test string with various items to insert.

It also has some #!invalid!# replacement #!keys!# to test the escaping and restoring.

Here is the default output language: [en_CA]
Here we will inject 't_0000': [Test replace: [result!].] 
Here we will inject 't_0002' with its embedded variables: [Test Out of order: [2nd] replace: [1st].]
Here we will inject 't_0006', which injects 't_0001' which has a variable: [This string embeds 't_0001': [Test replace: [result!].]].
", "Verifying string processing in the default (Canadian English) language.");
is($an->Words->string({
	language  => 'jp',
	key       => 't_0005',
	variables => {
		test   => "result!",
		first  => "1st",
		second => "2nd",
 	},
}), "
これは、挿入するさまざまな項目を含む複数行のテスト文字列です。

#!無効#!な置換!#キー!#を使ってエスケープとリストアをテストすることもできます。

デフォルトの出力言語は次のとおりです：「en_CA」
ここで、「t_0000」を挿入します：[テスト いれかえる: [result!]。]
ここでは、 「t_0002」に埋め込み変数を挿入します：「テスト、 整理: [2nd]/[1st]。」
ここでは変数 「この文字列には「t_0001」が埋め込まれています：「テスト いれかえる: [result!]。」」を持つ 「t_0001」を注入する 「t_0006」を注入します。
", "Verifying string processing in Japanese.");

### Get tests.
like($an->Get->date_and_time(), qr/^\d\d\d\d\/\d\d\/\d\d \d\d:\d\d:\d\d$/, "Verifying the current date and time is returned.");
like($an->Get->date_and_time({date_only => 1}), qr/^\d\d\d\d\/\d\d\/\d\d$/, "Verifying the current date alone is returned.");
like($an->Get->date_and_time({time_only => 1}), qr/^\d\d:\d\d:\d\d$/, "Verifying the current time alone is returned.");
like($an->Get->date_and_time({file_name => 1}), qr/^\d\d\d\d-\d\d-\d\d_\d\d-\d\d-\d\d$/, "Verifying the current date and time is returned in a file-friendly format.");
like($an->Get->date_and_time({file_name => 1, date_only => 1}), qr/^\d\d\d\d-\d\d-\d\d$/, "Verifying the current date only is returned in a file-friendly format.");
like($an->Get->date_and_time({file_name => 1, time_only => 1}), qr/^\d\d-\d\d-\d\d$/, "Verifying the current time only is returned in a file-friendly format.");
# We can't be too specific because the user's TZ will shift the results
like($an->Get->date_and_time({use_time => 1234567890}), qr/2009\/02\/1[34] \d\d:\d\d:\d\d$/, "Verified that a specific unixtime returned the expected date.");
like($an->Get->date_and_time({use_time => 1234567890, offset => 31536000}), qr/2010\/02\/1[34] \d\d:\d\d:\d\d$/, "Verified that a specific unixtime with a one year in the future offset returned the expected date.");
like($an->Get->date_and_time({use_time => 1234567890, offset => -31536000}), qr/2008\/02\/1[34] \d\d:\d\d:\d\d$/, "Verified that a specific unixtime with a one year in the past offset returned the expected date.");

# my $time     = time;
# print "Current time: .............. [".$an->Get->date_and_time({})."]\n";
# print "Current time only: ......... [".$an->Get->date_and_time({time_only => 1})."]\n";
# print "Current date only: ......... [".$an->Get->date_and_time({date_only => 1})."]\n";
# print "Current file time: ......... [".$an->Get->date_and_time({file_name => 1})."]\n";
# print "Current file time only: .... [".$an->Get->date_and_time({file_name => 1, time_only => 1})."]\n";
# print "Current file date only: .... [".$an->Get->date_and_time({file_name => 1, date_only => 1})."]\n";
# print "One hour ago: .............. [".$an->Get->date_and_time({offset => -3600})."]\n";
# print "Ten hours from now: ........ [".$an->Get->date_and_time({offset => 36000})."]\n";
# print "Ten hours ago: ............. [".$an->Get->date_and_time({offset => -36000})."]\n";
