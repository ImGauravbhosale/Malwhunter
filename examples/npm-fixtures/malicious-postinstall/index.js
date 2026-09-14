module.exports = function leftPad(str, len, ch) {
  ch = ch || " ";
  str = String(str);
  while (str.length < len) {
    str = ch + str;
  }
  return str;
};
