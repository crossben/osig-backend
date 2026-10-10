"""
Phone Intelligence Module

This module gathers intelligence on phone numbers using the phonenumbers library.
It can validate phone numbers, determine their country/region, identify carrier,
and check if the number is mobile or landline.

This module uses libphonenumber (Google's phone number parsing library) via
the Python phonenumbers package.
"""

from typing import List, Dict, Any, Optional
import phonenumbers
from phonenumbers import geocoder, carrier, timezone
from phonenumbers.phonenumberutil import NumberParseException
from app.osint.base import BaseOSINTModule, OSINTResult


class PhoneIntelModule(BaseOSINTModule):
    """
    Phone number Intelligence gathering module.
    
    This module investigates phone numbers to find:
    - Country and region
    - Carrier/operator name
    - Number type (mobile, landline, VoIP, etc.)
    - Timezone information
    - Validation status
    """
    
    def __init__(self):
        """Initialize the Phone Intel module."""
        super().__init__(
            name="phone_intel",
            display_name="Phone Intelligence"
        )
    
    def run(self, target: str) -> List[OSINTResult]:
        """
        Execute phone number intelligence gathering.
        
        Args:
            target: Phone number to investigate (can include country code)
            
        Returns:
            List of findings about the phone number
        """
        self.log_start(target)
        results = []
        
        # Validate phone number
        if not self.validate_target(target, "phone"):
            self.logger.warning(f"Invalid phone number format: {target}")
            return results
        
        try:
            # Parse and analyze the phone number
            phone_data = self._analyze_phone_number(target)
            
            if phone_data:
                # Create result object with all phone number information
                result = OSINTResult(
                    source="phonenumbers (libphonenumber)",
                    source_url="https://github.com/google/libphonenumber",
                    data_type="phone_info",
                    data=phone_data,
                    # High confidence if number is valid, lower if invalid
                    confidence=0.95 if phone_data.get("is_valid") else 0.5
                )
                results.append(result)

                numverify = self._numverify(phone_data.get("e164_format") or target)
                if numverify:
                    results.append(numverify)
                
            self.log_success(len(results))
            
        except Exception as e:
            self.log_error(e)
            raise
        
        return results
    
    def _numverify(self, number: str) -> Optional[OSINTResult]:
        """Line validity, carrier and line type from numverify (when NUMVERIFY_API_KEY is set)."""
        from app.core.config import settings
        if not settings.NUMVERIFY_API_KEY:
            return None
        import httpx
        try:
            r = httpx.get("https://apilayer.net/api/validate", timeout=12,
                          params={"access_key": settings.NUMVERIFY_API_KEY, "number": number.lstrip("+")})
            d = r.json()
        except Exception as e:
            self.logger.info(f"numverify failed: {e}")
            return None
        if "error" in d:
            return None
        return OSINTResult(
            source="numverify",
            source_url="https://numverify.com",
            data_type="phone_info",
            data={"valid": d.get("valid"), "carrier": d.get("carrier") or None, "line_type": d.get("line_type"),
                  "location": d.get("location") or None, "country": d.get("country_name")},
            confidence=0.85,
        )

    def _analyze_phone_number(self, phone: str) -> Optional[Dict[str, Any]]:
        """
        Analyze phone number using phonenumbers library.
        
        The phonenumbers library can extract a lot of information from a phone number:
        - Validity (is it a real, possible number?)
        - Country (which country does it belong to?)
        - Region (state/province within country)
        - Carrier (T-Mobile, AT&T, etc.)
        - Type (mobile, landline, toll-free, etc.)
        - Timezone (what timezone is this number in?)
        
        Args:
            phone: Phone number string (with or without country code)
            
        Returns:
            Dictionary with phone number analysis, or None if parsing fails
        """
        try:
            # Step 1: Parse the phone number
            # We try to parse without country hint first
            # If that fails, we try common country codes
            parsed = None
            
            try:
                # Try parsing as international format (+1234567890)
                parsed = phonenumbers.parse(phone, None)
            except NumberParseException:
                # If that fails, try with common country codes
                # Common codes: US (+1), UK (+44), FR (+33), DE (+49)
                for region in ['US', 'GB', 'FR', 'DE', 'CA', 'AU']:
                    try:
                        parsed = phonenumbers.parse(phone, region)
                        if phonenumbers.is_valid_number(parsed):
                            break  # Found valid parsing
                    except NumberParseException:
                        continue
            
            # If we couldn't parse it at all, return None
            if not parsed:
                self.logger.warning(f"Could not parse phone number: {phone}")
                return None
            
            # Step 2: Extract information from parsed number
            
            # Get country code and region
            country_code = parsed.country_code
            national_number = parsed.national_number
            region_code = phonenumbers.region_code_for_number(parsed)
            
            # Get geographic description (e.g., "New York, NY")
            location = geocoder.description_for_number(parsed, "en")
            
            # Get carrier name (e.g., "AT&T", "Verizon")
            carrier_name = carrier.name_for_number(parsed, "en")
            
            # Get timezone(s) - a number can be in multiple timezones
            timezones = timezone.time_zones_for_number(parsed)
            
            # Check validity
            is_valid = phonenumbers.is_valid_number(parsed)
            is_possible = phonenumbers.is_possible_number(parsed)
            
            # Get number type (mobile, fixed-line, etc.)
            number_type = phonenumbers.number_type(parsed)
            type_mapping = {
                0: "fixed_line",
                1: "mobile",
                2: "fixed_line_or_mobile",
                3: "toll_free",
                4: "premium_rate",
                5: "shared_cost",
                6: "voip",
                7: "personal_number",
                8: "pager",
                9: "uan",  # Universal Access Number
                10: "voicemail",
                -1: "unknown"
            }
            number_type_str = type_mapping.get(number_type, "unknown")
            
            # Format the number in different ways
            international_format = phonenumbers.format_number(
                parsed, 
                phonenumbers.PhoneNumberFormat.INTERNATIONAL
            )
            national_format = phonenumbers.format_number(
                parsed,
                phonenumbers.PhoneNumberFormat.NATIONAL
            )
            e164_format = phonenumbers.format_number(
                parsed,
                phonenumbers.PhoneNumberFormat.E164
            )
            
            # Step 3: Compile all information into a dictionary
            return {
                # Basic info
                "original_input": phone,
                "is_valid": is_valid,
                "is_possible": is_possible,
                
                # Number components
                "country_code": country_code,
                "national_number": str(national_number),
                "region_code": region_code,
                
                # Geographic info
                "location": location if location else "Unknown",
                "carrier": carrier_name if carrier_name else "Unknown",
                "timezones": list(timezones) if timezones else [],
                
                # Number type
                "number_type": number_type_str,
                
                # Formatted versions
                "international_format": international_format,
                "national_format": national_format,
                "e164_format": e164_format,
            }
            
        except NumberParseException as e:
            # Phone number parsing failed
            self.logger.error(f"Failed to parse phone number {phone}: {str(e)}")
            return None
        except Exception as e:
            # Other unexpected error
            self.logger.error(f"Error analyzing phone number: {str(e)}")
            return None


# Create module instance for easy import
phone_intel = PhoneIntelModule()
