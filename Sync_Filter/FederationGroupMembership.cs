//------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated from a template.
//
//     Manual changes to this file may cause unexpected behavior in your application.
//     Manual changes to this file will be overwritten if the code is regenerated.
// </auto-generated>
//------------------------------------------------------------------------------

namespace security_sync_filter
{
    using System;
    using System.Collections.Generic;
    
    public partial class FederationGroupMembership
    {
        public int Id { get; set; }
        public byte[] RowVersion { get; set; }
        public System.DateTime TimeStamp { get; set; }
        public int FederationGroupMembershipItem_ADUser { get; set; }
        public int FederationGroupMembershipItem_FederationGroup { get; set; }
    
        public virtual ADUser ADUser { get; set; }
        public virtual FederationGroup FederationGroup { get; set; }
    }
}
