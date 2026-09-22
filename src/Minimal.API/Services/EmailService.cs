using Resend;

namespace Minimal.API.Services;

internal sealed class EmailService(IResend resend)
{
    public async Task
    SendAsync(
        string to,
        string subject,
        string html)
    {
        var message =
            new EmailMessage
            {
                From =
                    "Minimal API <onboarding@resend.dev>",

                Subject = subject,
                HtmlBody = html
            };

        message.To.Add(to);

        await resend.EmailSendAsync(message);
    }
}