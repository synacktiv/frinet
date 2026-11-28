use frinet_db::search::{Pattern, PatternError};

const EMPTY: &str = "empty pattern is not supported";
const LOOK_AROUND: &str = "look-around (`^`, `$`, `\\b`) is not supported";

#[test]
fn patterns_are_accepted_or_rejected() {
    assert!(Pattern::parse("abc").is_ok());
    assert!(Pattern::parse(r"[a-z]+\x00").is_ok());
    assert!(Pattern::parse("(a|b){2,4}").is_ok());
    assert!(Pattern::parse(r"\x41{3}").is_ok());
    assert!(Pattern::parse("a?b*c+").is_ok());
    assert!(Pattern::parse("(?:ab|cd)e").is_ok());
    assert!(Pattern::parse("[^a]").is_ok());
    assert!(Pattern::parse(".").is_ok());

    assert_eq!(parse_error(""), EMPTY);
    assert_eq!(parse_error("()"), EMPTY);
    assert_eq!(parse_error("a|"), EMPTY);
    assert_eq!(parse_error("(?:)*"), EMPTY);

    // look-around, also nested in a group, an alternation and a repetition
    assert_eq!(parse_error("^abc"), LOOK_AROUND);
    assert_eq!(parse_error("abc$"), LOOK_AROUND);
    assert_eq!(parse_error(r"\babc"), LOOK_AROUND);
    assert_eq!(parse_error(r"abc\B"), LOOK_AROUND);
    assert_eq!(parse_error("(?:^|a)b"), LOOK_AROUND);
    assert_eq!(parse_error("a(b|$)"), LOOK_AROUND);
    assert_eq!(parse_error("(^a)*"), LOOK_AROUND);

    // syntax errors keep the message of regex-syntax
    assert!(parse_error("[").contains("unclosed character class"));
    assert!(parse_error("(a").contains("unclosed group"));
    assert!(parse_error("a{2,1}").contains("invalid repetition count range"));
}

#[test]
fn arbitrary_bytes_are_accepted() {
    assert!(Pattern::literal(&[0x00]).is_ok());
    assert!(Pattern::literal(&[0xff]).is_ok());
    assert!(Pattern::literal(b"^$").is_ok());
    assert!(Pattern::literal(b"\\b").is_ok());
    assert!(Pattern::literal(b"[").is_ok());

    // every byte value, including non UTF-8 ones and regex metacharacters taken literally
    let all_bytes: Vec<u8> = (0..=u8::MAX).collect();
    assert!(Pattern::literal(&all_bytes).is_ok());

    assert!(Pattern::parse(r"\x00").is_ok());
    assert!(Pattern::parse(r"\xff").is_ok());
    assert!(Pattern::parse(r"\x00\xff").is_ok());
    assert!(Pattern::parse(r"[\x80-\xff]+").is_ok());
    assert!(Pattern::parse(r"[^\x00]").is_ok());
    assert!(Pattern::parse(r"(?:\xde\xad|\xbe\xef){2}").is_ok());

    assert_eq!(error(Pattern::literal(b"")).to_string(), EMPTY);
}

fn error(result: Result<Pattern, PatternError>) -> PatternError {
    match result {
        Ok(_) => panic!("the pattern should be rejected"),
        Err(err) => err,
    }
}

fn parse_error(regex: &str) -> String {
    error(Pattern::parse(regex)).to_string()
}
