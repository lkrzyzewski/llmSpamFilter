# llmSpamFilter
Solution to use small LLMs like Gemma1B or Bielik_1.5B to categorize spam and potential emails

The idea is to use small LLMs to identify potential phishing attempts and to help anti-spam filters categorize emails.

The system using exim4 as the Mail Transport Agent (MTA) and Amavis as the spam filter. In a standard configuration, the MTA receives an email and passes it to Amavis for categorization, after which it returns to the MTA. I modified the configuration so that emails first go to an SMTP server handling LLMs and then to Amavis.

I used two separate LLMs: one for categorizing potential phishing and another for categorizing spam.

Fine-tuning data primarily came from local emails. Phishing data is difficult to collect in large quantities. In this case, in addition to several hundred collected emails, I supplemented my dataset with Nazario's collection from Kaggle: https://www.kaggle.com/datasets/naserabdullahalam/phishing-email-dataset. For spam, the dataset consisted of approximately 11,000 emails, split 50/50 between spam and ham. For phishing, there were around 2,100 phishing emails and approximately 3,000 legitimate emails.

Initially, I used the Gemma3_1b model for fine-tuning. The results were satisfactory, with very good phishing categorization and good generalization. Unfortunately, there were quite a few False Positives, which I partially mitigated through a whitelist. Next, I tried the speaklesh/Bielik-1.5B-v3.0-Instruct model, which resulted in fewer False Positives while maintaining very good detection of potential phishing. However, the larger Bielik model: speaklesh/Bielik-4.5B-v3.0-Instruct proved to be the best for this purpose. For spam categorization, I ultimately stuck with the smaller Bielik version: 1.5B.

Model handling is divided between two servers. The first is an SMTP server running on the MTA, and the second is a FastAPI-based server running on a GPU machine. Emails categorized as spam have an "AIspam: Yes" header added, which is then used in SpamAssassin rules to apply a score. The score value needs to be set individually; in my case, it's 4 with a spam threshold of 7. Emails categorized as phishing have the prefix [SUSPICIOUS] added to the subject line, as the system identifies potential phishing and cannot distinguish between genuine and impersonated legitimate emails. This requires additional processes, such as analyzing links within emails.

The final result exceeded expectations: spam filtering increased from approximately 60-70% to over 90%. By adding phishing emails (most commonly those related to "pending messages" or "password changes") that are frequently received to the spam model's training data, I was also able to eliminate the most common phishing attempts that are 100% confirmed as phishing.

The cost is the rental of one GPU machine (20GB VRAM) at approximately $100 per month.
