package GitHub::Authorization;

# ABSTRACT: Generate a gitHub OAuth2 non-web authorization token

use strict;
use warnings;
use Carp 'confess';

use autobox::JSON;
use HTTP::Tiny;
use MIME::Base64;
#use Params::Validate;

# for SSL and SSL CA verification
use IO::Socket::SSL 1.56;
use Mozilla::CA;

use Sub::Exporter::Progressive -setup => {
    exports => [ qw{ get_gh_token } ],
    groups => {
        default => [ 'get_gh_token' ],
    },
};

# debugging...
use Smart::Comments '###';

my %scopes =
    map { $_ => 1 }
    qw{ public_repo repo repo:status delete_repo notifications gist }
    ;

sub _default_agent {
    'GitHub::Authorization/'
    . (__PACKAGE__->VERSION || 0)
    . q{ }
}

sub _url { 'https://api.github.com' . shift }

=func get_gh_token($user, $password, [ $scopes, $note, $note_uri ])

We take 2 mandatory parameters (user and password), and two optional
parameters: an arrayref of scopes and a note that will appear as the name on
the "Authorized Applications" status list.

We throw an exception on error or failure, and return the structure describing
the new authorization token (and the token itself, as described below) on
success.

On failure, we confess() our sins:

    Failed: 401/Unauthorized / Bad credentials ...

That is, we L<Carp/confess> with the status code, status message, and the
message returned from GitHub itself.

=cut

sub get_gh_token {
    my ($user, $password, $scopes, $note) = @_;

    $scopes ||= [];

    my @illegal =
        map  { "illegal_scope: $_" }
        grep { ! $scopes{$_}       }
        @$scopes;

    push @illegal, "user not supplied"
        unless defined $user && length $user > 0;
    push @illegal, "password not supplied"
        unless defined $password && length $password > 0;

    confess "Bad options: @illegal"
        if @illegal;

    # now, to the real stuff

    my $ua = HTTP::Tiny->new(
        agent      => _default_agent,
        verify_SSL => 1,
    );

    my $url     = _url('/authorizations');
    my $hash    = MIME::Base64::encode_base64("$user:$password", '');
    my $headers = { Authorization => 'Basic ' . $hash };
    my $content = { scopes => $scopes, note => $note };

    ### $url
    ### $headers
    ### $content

    my $res = $ua->post($url, {
        headers => $headers,
        content => $content->to_json,
    });

    ### $res;

    confess "Failed: $res->{status}/$res->{reason} / " . $res->{content}->from_json->{message}
        unless $res->{success};

    return $res->{content}->from_json;
}

!!42;
__END__

=head1 SYNOPSIS

    use GitHub::Authorization;

    # ...

    my $token_info = get_gh_token('RsrchBoy', '*****', ['gist'], 'test!')
    my $token      = $token_info->{token};

=head1 DESCRIPTION

There are a number of good packages on the CPAN to handle working with the
L<GitHub API|http://developer.github.com/v3>, but none that provide a
(relatively) lightweight, straight-forward way to generate OAuth2 tokens.

This package implements the procedure described in
L<GitHub Developer's Guide "Non-Web Application
Flow"|http://developer.github.com/v3/oauth/#non-web-application-flow> to
create authorization tokens; that is, authoriation tokens tht can be stored,
managed, reused and revoked without needing to store (or otherwise acquire) a
user password.

=head1 OVERVIEW

=head2 Exports

We do not export anything by default; L<Sub::Exporter::Progressive> is used
here so you can either use plain-old L<Exporter> or fancy-new L<Sub::Exporter>
syntax; whatever you desire or require.

=head2 Technologies

This package uses and returns OAuth2 authorization tokens, and uses V3 of the
GitHub API.  (Both the latest supported.)

=head2 Legal Scopes

The formal list of supported scops can be found at the L<GitHub OAuth API
reference|http://developer.github.com/v3/oauth/#scopes> (note this list is
taken almost verbatim from that page).  If a scope appears
there but not here, please file an issue against this package (as the author
has likely not noticed it yet).

=for :list
* (no scopes given)
public read-only access (includes public user profile info, public repo info, and gists).
* user
Read/write access to profile info only.
* public_repo
Read/write access to public repos and organizations.
* repo
Read/write access to public and private repos and organizations.
* repo:status
Read/write access to public and private repo statuses. Does not include access to code - use repo for that.
* delete_repo
Delete access to adminable repositories.
* notifications
Read access to a user’s notifications. repo is accepted too.
* gist
write access to gists.

=head2 RETURNED STRUCTURES

A successful return from get_gh_token() will look something like this:

    {
        app => {
            name => "test! (API)",
            url  => "http://developer.github.com/v3/oauth/#oauth-authorizations-api",
        },
        created_at => "2012-12-24T14:28:17Z",
        id         => xxxxxxx, # an integer > 0
        note       => "test!",
        note_url   => undef,
        scopes     => ["public_repo"],
        token      => "****************************************",
        updated_at => "2012-12-24T14:28:17Z",
        url        => "https://api.github.com/authorizations/xxxxxxx",
    }

=head2 MANAGING AUTHORIZATIONS

All of a user's GitHub authorization tokens can be viewed and revoked on their
L<GitHub Applications|https://github.com/settings/applications> account page.

=head2 SSL VALIDATION

We instruct our user-agent (L<HTTP::Tiny in this case) to validate the remote
server's certificate, as described in L<HTTP::Tiny/SSL-SUPPORT>.
(Essentially, using L<Mozilla::CA>).

While this satisfies the "let's be cautious" alarms in the author's head,
this may be too paranoid or not paranoid enough for you.  If so, please file
an issue or pull request and we'll work something out.

=head1 SEE ALSO

The GitHub OAuth API reference at L<http://developer.github.com/v3/oauth/#create-a-new-authorization>

L<Net::GitHub>, L<Pithub>, and the other packages that use them.

=cut
