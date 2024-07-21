# Message Translator Tool

## Lambda
- https://us-east-2.console.aws.amazon.com/lambda/home?region=us-east-2#/functions/MessageTranslatorTool?newFunction=true&tab=code

## Local Development
- After modifying JavaScript code, run `npm run build`
- After modifying lambda code, run `./ship_lambda.sh`, then upload the zip file from `~/Desktop` to the lambda in AWS

## Deploying
In GitHub: `Actions` > `Deploy static content to Pages`