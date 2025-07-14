import typer
import logging

from rollupc.providers.aws_kms import AWSKMSProvider

logger = logging.getLogger(__name__)
app = typer.Typer()


@app.command()
def hello(name: int):
    """Prints a greeting message with the provided name."""
    logger.info(f"Hello, {name}!")


@app.command()
def get_pubkey(
    arn: str = typer.Option(None, help="ARN of the KMS key to use for decryption"),
):
    logger.info(f"Getting public key for ARN: {arn}")
    provider = None
    if arn:
        provider = AWSKMSProvider(key_id=arn)
    else:
        logger.error("Error: you must specify a KMS key ARN or set 'new' to true.")
        raise typer.Exit(code=1)

    logger.info(f"Public key: {provider.get_public_key()}")


def setup_logging(verbose: bool):
    """Sets up logging configuration based on verbosity."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="%(asctime)s | %(levelname)s | %(message)s")


@app.callback()
def main_callback(
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Enable verbose logging"
    ),
):
    """Main entry point for the application."""
    setup_logging(verbose)


if __name__ == "__main__":
    app()
