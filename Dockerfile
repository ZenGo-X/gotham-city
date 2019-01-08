FROM 542401451332.dkr.ecr.us-west-2.amazonaws.com/gothambuild:latest

EXPOSE 8080
CMD ["$HOME/.cargo/bin/cargo", "run", "--release"]



