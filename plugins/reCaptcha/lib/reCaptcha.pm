##############################################################################
# Copyright © 2010 Six Apart Ltd.
# This program is free software: you can redistribute it and/or modify it
# under the terms of version 2 of the GNU General Public License as published
# by the Free Software Foundation, or (at your option) any later version.
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
# version 2 for more details.  You should have received a copy of the GNU
# General Public License version 2 along with this program. If not, see
# <http://www.gnu.org/licenses/>.

package reCaptcha;

use strict;
use warnings;
use base qw(MT::ErrorHandler);

sub debuglog {
    return unless MT->config->ReCaptchaDebug;
    my $msg = shift || return;
    require MT;
    MT->log({
        message => "reCaptcha: $msg",
        level   => MT::Log::DEBUG(),
    });
}

sub form_fields {
    my $self = shift;
    my ($blog_id) = @_;

    my $plugin = MT::Plugin::reCaptcha->instance;
    my $config = $plugin->get_config_hash("blog:$blog_id");
    my $publickey = $config->{recaptcha_publickey};
    my $privatekey = $config->{recaptcha_privatekey};
    return q() unless $publickey && $privatekey;

    return <<FORM_FIELD;
<div class="g-recaptcha" data-sitekey="$publickey"></div>
FORM_FIELD
}

sub validate_captcha {
    my $self = shift;
    my ($app) = @_;

    my $blog_id = $app->param('blog_id');
    if ( my $entry_id = $app->param('entry_id') ) {
        my $entry = $app->model('entry')->load($entry_id)
            or return 0;
        $blog_id = $entry->blog_id;
    };
    return 0 unless $blog_id;
    return 0 unless $app->model('blog')->count( { id => $blog_id } );

    my $config = MT::Plugin::reCaptcha->instance->get_config_hash("blog:$blog_id");
    my $privatekey = $config->{recaptcha_privatekey};

    my $response = $app->param('g-recaptcha-response');
    my $ua = $app->new_ua({ timeout => 15, max_size => undef });
    return 0 unless $ua;

    require HTTP::Request;
    my $req = HTTP::Request->new(POST => 'https://www.google.com/recaptcha/api/siteverify');
    $req->content_type("application/x-www-form-urlencoded");
    require MT::Util;
    my $content = 'secret=' . MT::Util::encode_url($privatekey);
    $content .= '&response=' . MT::Util::encode_url($response);
    $req->content($content);
    debuglog("sending verification request: '$content'");

    my $res = $ua->request($req);
    my $c = $res->content;

    if ($c =~ /true/)
    {
      debuglog("submitted code is valid: '$c'");
      return 1;
    }   
    
    debuglog("submitted code is not valid: '$s'");
    return 0;
}

sub generate_captcha {
    # This won't be called since there is no link which requests to "generate_captcha" mode.
    my $self = shift;
    1;
}

1;
