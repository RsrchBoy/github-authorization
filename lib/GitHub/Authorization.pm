package GitHub::Authorization;

# ABSTRACT: Generate a GitHub OAuth2 non-web authorization token

use strict;
use warnings;
use Carp 'confess';

use autobox::JSON;
use HTTP::Tiny;
use IO::Prompt::Tiny 'prompt';
use MIME::Base64;
use Params::Validate ':all';

# for SSL and SSL CA verification
use IO::Socket::SSL 1.56;
use Mozilla::CA;

use namespace::clean;

use Sub::Exporter::Progressive -setup => {
    exports => [ qw{ is_legal_scope legal_scopes get_gh_token } ],
};

sub _default_agent {
    'GitHub::Authorization/'
    . (__PACKAGE__->VERSION || 0)
    . q{ }
}

sub _url { 'https://api.github.com' . shift }

=func get_gh_token(user => Str, password => Str, ...)

B<NOTE: Validate your parameters!>  We do basic validation, but nothing
strenuous.

We take 2 mandatory parameters (user and password), and can take several more
optional ones:

=head3 Parameters

=for :list
* user (required)
The user-name or email of the user the authorization is being created against.
* password (required)
The user's password.
* scopes
An ArrayRef of scopes (described L</Legal Scopes>).
* note
A short note (or reminder) describing what the authorization is for.
* note_url
A link that describes why the authorization has been generated
We throw an exception on error or failure, and return the structure describing
the new authorization token (and the token itself, as described below) on
success.
* client_id (required if client_secret is given)
If requesting an authorization for a specific app, pass its client key here.
* client_secret (required if client_id is given)
If requesting an authorization for a specific app, pass its client secret here.

=head3 On success...

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

The C<token> slot is probably the bit you want.

=head3 On failure/error...

On failure, we confess() our sins:

    Failed: 401/Unauthorized / Bad credentials ...

That is, we L<Carp/confess> with the status code, status message, and the
message returned from GitHub itself.

=cut

sub get_gh_token {

    my %_opt = ( type => SCALAR | UNDEF, optional => 1 );
    my %args = validate @_ => {
        user          => { type => SCALAR,   regex => qr/^[A-Za-z0-9\.@]+$/ },
        password      => { type => SCALAR                                   },
        scopes        => { type => ARRAYREF, default => [ ]                 },

        # 2fa callback
        otp_callback => {
            type    => CODEREF,
            default => sub { prompt 'Two-factor OTP:' },
        },

        # optional args
        note          => { %_opt                              },
        note_url      => { %_opt                              },
        client_id     => { %_opt, regex => qr/^[a-f0-9]{20}$/ },
        client_secret => { %_opt, regex => qr/^[a-f0-9]{40}$/ },
    };

    my ($user, $password, $scopes, $otp_callback)
        = delete @args{qw{user password scopes otp_callback}};

    $scopes ||= [];

    my @illegal =
        map  { "illegal_scope: $_"  }
        grep { ! is_legal_scope($_) }
        @$scopes;

    confess "Bad scopes: @illegal"
        if @illegal;

    $args{scopes} = $scopes
        if @$scopes;

    # now, to the real stuff

    my $ua = HTTP::Tiny->new(
        agent      => _default_agent,
        verify_SSL => 1,
    );

    my $url     = _url('/authorizations');
    my $hash    = MIME::Base64::encode_base64("$user:$password", '');
    my $headers = { Authorization => 'Basic ' . $hash };
    my $content = { scopes => $scopes, %args };

    ### $url
    ### $headers
    ### $content

    my $res = $ua->post($url, {
        headers => $headers,
        content => $content->to_json,
    });

    if ($res->{status} == 401 && $res->{headers}->{'x-github-otp'}) {

        ### need to prompt for GH OTP auth: $res
        my $otp = $otp_callback->($res)
            or confess 'Could not acquire OTP from user';

        $res = $ua->post($url, {
            headers => {
                %$headers,
                'X-GitHub-OTP' => $otp,
            },
            content => $content->to_json,
        });
    }

    ### $res

    confess "Failed: $res->{status}/$res->{reason} / " . $res->{content}->from_json->{message}
        unless $res->{success};

    return $res->{content}->from_json;
}

=func legal_scopes

Returns a list of legal scope names.  (See get_gh_token() doc for the list)

=func is_legal_scope('scope_name')

Returns true if the scope name given is a legal scope.

=cut

{
    my %scopes =
        map { $_ => 1 }
        qw{
            user user:email user:follow public_repo repo repo:status
            delete_repo notifications gist
        }, q{}
        ;

    sub legal_scopes   { sort keys %scopes     }
    sub is_legal_scope { $scopes{shift || q{}} }
}

!!42;
__END__

=for :stopwords OAuth OAuth2 Str repo repos gists adminable unfollow

=head1 SYNOPSIS

    use GitHub::Authorization;

    my $token_info = get_gh_token(
        user     => 'RsrchBoy',
        password => '*****',
        scopes   => ['repo'],
        note     => 'test!',
    );
    my $token      = $token_info->{token};

    # e.g.
    use Net::GitHub;
    my $gh = Net::GitHub->new(access_token => $token, ...);

    # ... or ...
    use Pithub;
    my $ph = Pithub->new(token => $token, ...);

=head1 DESCRIPTION

There are a number of good packages on the CPAN to handle working with the
L<GitHub API|http://developer.github.com/v3>, but none that provide a
(relatively) lightweight, straight-forward way to generate OAuth2 tokens.

This package implements the procedure described in
L<GitHub Developer's Guide "Non-Web Application
Flow"|http://developer.github.com/v3/oauth/#non-web-application-flow> to
create authorization tokens; that is, authorization tokens that can be
stored, managed, reused and revoked without needing to store (or
otherwise acquire) a user password.

=head2 Exports

We do not export anything by default; L<Sub::Exporter::Progressive> is used
here so you can either use plain-old L<Exporter> or fancy-new L<Sub::Exporter>
syntax; whatever you desire or require.

=head2 Technologies

This package uses and returns OAuth2 authorization tokens, and uses V3 of the
GitHub API.

=head2 Legal Scopes

The formal list of supported scopes can be found at the L<GitHub OAuth API
reference|http://developer.github.com/v3/oauth/#scopes> (note this list is
taken almost verbatim from that page).  If a scope appears
there but not here, please file an issue against this package (as the author
has likely not noticed it yet).

=for :list
* (no scopes given)
public read-only access (includes public user profile info, public repo info, and gists).
* user
Read/write access to profile info only. Note: this scope includes C<user:email> and C<user:follow>.
* user:email
Read access to a user’s email addresses.
* user:follow
Access to follow or unfollow other users.
* public_repo
Read/write access to public repos and organizations.
* repo
Read/write access to public and private repos and organizations.
* repo:status
Read/write access to public and private repository commit statuses. This scope is only necessary to grant other users or services access to private repository commit statuses without granting access to the code. The C<repo> and C<public_repo> scopes already include access to commit status for private and public repositories respectively.
* delete_repo
Delete access to adminable repositories.
* notifications
Read access to a user’s notifications. repo is accepted too.
* gist
Write access to gists.

=head1 MANAGING AUTHORIZATIONS

All of a user's GitHub authorization tokens can be viewed and revoked on their
L<GitHub Applications|https://github.com/settings/applications> account page.

Users may revoke tokens at any time through GitHub proper.

=head1 SSL VALIDATION

We instruct our user-agent (L<HTTP::Tiny> in this case) to validate the remote
server's certificate, as described in L<HTTP::Tiny/SSL-SUPPORT>.
(Essentially, using L<Mozilla::CA>).

While this satisfies the "let's be cautious" alarms in the author's head,
this may be too paranoid or not paranoid enough for you.  If so, please file
an issue or pull request and we'll work something out.

=head1 LIMITATIONS

This package currently has no capabilities for deleting, altering, or
otherwise doing anything with tokens outside of creating them.

=head1 SEE ALSO

L<The GitHub OAuth API reference|http://developer.github.com/v3/oauth/#create-a-new-authorization>
L<Net::GitHub>
L<Pithub>

=cut
